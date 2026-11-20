"""TS-A2: typed config, env expansion, line-numbered errors."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_shield.config import (
    ConfigError,
    HttpServer,
    PolicyFile,
    ServersFile,
    StdioServer,
    json_schemas,
    load_config,
    load_yaml_model,
    policy_hash,
)


def write(tmp: Path, name: str, text: str) -> Path:
    p = tmp / name
    p.write_text(text)
    return p


def test_valid_servers_file_parses_both_transports(tmp_path: Path) -> None:
    p = write(
        tmp_path,
        "servers.yaml",
        """
servers:
  - id: fs
    transport: stdio
    command: ["npx", "-y", "@modelcontextprotocol/server-filesystem", "./sandbox"]
  - id: github
    transport: http
    url: https://example.internal/mcp
    headers: { Authorization: "Bearer ${GH_TOKEN}" }
""",
    )
    cfg = load_yaml_model(p, ServersFile, env={"GH_TOKEN": "secret"})
    fs, gh = cfg.servers
    assert isinstance(fs, StdioServer) and fs.command[0] == "npx"
    assert isinstance(gh, HttpServer) and gh.headers["Authorization"] == "Bearer secret"


def test_bad_transport_error_cites_the_line(tmp_path: Path) -> None:
    p = write(
        tmp_path,
        "servers.yaml",
        """servers:
  - id: fs
    transport: stdio
    command: [node, server.js]
  - id: web
    transport: carrier-pigeon
    url: http://x
""",
    )
    with pytest.raises(ConfigError) as exc:
        load_yaml_model(p, ServersFile, env={})
    msg = str(exc.value)
    assert f"{p}:5:" in msg or f"{p}:6:" in msg
    assert "servers.1" in msg


def test_missing_env_var_is_reported_with_line(tmp_path: Path) -> None:
    p = write(
        tmp_path,
        "servers.yaml",
        """servers:
  - id: gh
    transport: http
    url: https://example/mcp
    headers: { Authorization: "Bearer ${MISSING_TOKEN}" }
""",
    )
    with pytest.raises(ConfigError) as exc:
        load_yaml_model(p, ServersFile, env={})
    assert f"{p}:5: environment variable ${{MISSING_TOKEN}} is not set" in str(exc.value)


def test_env_default_is_used(tmp_path: Path) -> None:
    p = write(
        tmp_path,
        "servers.yaml",
        """servers:
  - id: gh
    transport: http
    url: ${URL:-https://fallback.example/mcp}
""",
    )
    cfg = load_yaml_model(p, ServersFile, env={})
    assert cfg.servers[0].url == "https://fallback.example/mcp"  # type: ignore[union-attr]


@pytest.mark.parametrize("bad_id", ["Fs", "fs__x", "1fs", "x" * 33])
def test_server_ids_are_restricted(tmp_path: Path, bad_id: str) -> None:
    p = write(
        tmp_path, "servers.yaml", f"servers:\n  - id: {bad_id}\n    transport: stdio\n    command: [x]\n"
    )
    with pytest.raises(ConfigError):
        load_yaml_model(p, ServersFile, env={})


def test_duplicate_ids_rejected(tmp_path: Path) -> None:
    p = write(
        tmp_path,
        "servers.yaml",
        """servers:
  - {id: a, transport: stdio, command: [x]}
  - {id: a, transport: stdio, command: [y]}
""",
    )
    with pytest.raises(ConfigError, match="duplicate server id"):
        load_yaml_model(p, ServersFile, env={})


def test_unknown_keys_are_rejected(tmp_path: Path) -> None:
    p = write(tmp_path, "policy.yaml", "version: 1\ndefualts: {action: allow}\n")
    with pytest.raises(ConfigError) as exc:
        load_yaml_model(p, PolicyFile, env={})
    assert f"{p}:2:" in str(exc.value) and "defualts" in str(exc.value)


def test_rule_needs_an_effect(tmp_path: Path) -> None:
    p = write(tmp_path, "policy.yaml", "rules:\n  - id: noop\n    match: {tool: x}\n")
    with pytest.raises(ConfigError, match="needs an 'action' or a 'rate_limit'"):
        load_yaml_model(p, PolicyFile, env={})


def test_invalid_yaml_reports_line(tmp_path: Path) -> None:
    p = write(tmp_path, "policy.yaml", "rules:\n  - id: a\n   bad indent: [\n")
    with pytest.raises(ConfigError, match="invalid YAML"):
        load_yaml_model(p, PolicyFile, env={})


def test_policy_hash_ignores_formatting(tmp_path: Path) -> None:
    a = load_yaml_model(write(tmp_path, "a.yaml", "defaults: {action: allow}\n"), PolicyFile, env={})
    b = load_yaml_model(
        write(tmp_path, "b.yaml", "# comment\ndefaults:\n  action: allow\n"), PolicyFile, env={}
    )
    c = load_yaml_model(write(tmp_path, "c.yaml", "defaults: {action: deny}\n"), PolicyFile, env={})
    assert policy_hash(a) == policy_hash(b) != policy_hash(c)


def test_load_config_resolves_relative_paths(tmp_path: Path) -> None:
    write(tmp_path, "servers.yaml", "servers:\n  - {id: a, transport: stdio, command: [x]}\n")
    write(tmp_path, "policy.yaml", "version: 1\n")
    write(tmp_path, "pricing.yaml", "input_per_million: 3.0\n")
    shield = write(tmp_path, "shield.yaml", "pricing: pricing.yaml\naudit: {db_path: data/audit.db}\n")
    cfg = load_config(shield, env={})
    assert cfg.pricing and cfg.pricing.input_per_million == 3.0
    assert cfg.resolve(cfg.shield.audit.db_path) == tmp_path / "data/audit.db"
    assert cfg.policy_hash.startswith("p_") and cfg.policy_source == "version: 1\n"


def test_json_schemas_export() -> None:
    schemas = json_schemas()
    assert set(schemas) == {"shield", "servers", "policy", "pricing"}
    json.dumps(schemas)  # serialisable for editors


def test_examples_directory_is_valid() -> None:
    root = Path(__file__).resolve().parents[2] / "examples"
    cfg = load_config(root / "shield.yaml", env={})
    assert [s.id for s in cfg.servers.servers] == ["notes", "evil"]


@pytest.mark.parametrize("spelling", ["off", "Off", "OFF", "no", '"off"'])
def test_unquoted_off_means_off(tmp_path: Path, spelling: str) -> None:
    # YAML 1.1 reads bare off/no as false; for the scanner actions that can only mean "off".
    p = write(tmp_path, "policy.yaml", f"scanner: {{args_action: {spelling}, result_action: {spelling}}}\n")
    s = load_yaml_model(p, PolicyFile, env={}).scanner
    assert s.args_action == "off" and s.result_action == "off"


def test_true_is_still_rejected_for_scanner_actions(tmp_path: Path) -> None:
    p = write(tmp_path, "policy.yaml", "scanner: {args_action: on}\n")
    with pytest.raises(ConfigError, match=r"policy\.yaml:1: scanner\.args_action"):
        load_yaml_model(p, PolicyFile, env={})
