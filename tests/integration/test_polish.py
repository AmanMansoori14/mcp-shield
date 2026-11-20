"""Gap #15 `shield init`, #16 `shield check-policy`, #22 Overview KPI drill-down, #23 event click-through."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest
from typer.testing import CliRunner

from demo.seed_audit import seed
from mcp_shield.cli import app as cli
from mcp_shield.config import PolicyFile, load_config
from mcp_shield.security.policy_check import BUILTIN_CASES, CaseFile, run_cases

ROOT = Path(__file__).resolve().parents[2]
runner = CliRunner()


# --------------------------------------------------------------------------- #15 shield init


def test_init_writes_valid_config(tmp_path: Path) -> None:
    r = runner.invoke(cli, ["init", str(tmp_path)])
    assert r.exit_code == 0, r.output
    for name in ("shield.yaml", "servers.yaml", "policy.yaml"):
        assert (tmp_path / name).exists()
    cfg = load_config(tmp_path / "shield.yaml", env={})
    assert [s.id for s in cfg.servers.servers] == ["fs"] and cfg.policy.rules
    assert (tmp_path / "sandbox").is_dir()  # the sample filesystem server's root
    assert "shield check-policy" in r.output and "shield run" in r.output  # next steps


def test_init_asks_before_overwrite(tmp_path: Path) -> None:
    (tmp_path / "policy.yaml").write_text("# mine\n")
    r = runner.invoke(cli, ["init", str(tmp_path)], input="n\n")
    assert r.exit_code == 0 and "Overwrite" in r.output
    assert (tmp_path / "policy.yaml").read_text() == "# mine\n"  # kept
    assert (tmp_path / "shield.yaml").exists()  # the missing files are still written


def test_init_force_overwrites(tmp_path: Path) -> None:
    (tmp_path / "policy.yaml").write_text("# mine\n")
    r = runner.invoke(cli, ["init", str(tmp_path), "--force"])
    assert r.exit_code == 0 and "Overwrite" not in r.output
    assert "rules:" in (tmp_path / "policy.yaml").read_text()


# --------------------------------------------------------------------------- #16 check-policy


def example_policy() -> PolicyFile:
    return load_config(ROOT / "examples" / "shield.yaml", env={}).policy


def test_builtin_attacks_are_stopped_by_example_policy() -> None:
    results = run_cases(example_policy(), BUILTIN_CASES)
    assert len(results) == len(BUILTIN_CASES)
    by_id = {r.case.id: r for r in results}
    assert by_id["write-outside-sandbox"].outcome == "deny"
    assert by_id["write-outside-sandbox"].policy.rule_ids == ("deny-write-outside-sandbox",)
    traversal = by_id["path-traversal"]  # no policy rule; the argument scanner blocks it
    assert traversal.policy.action == "allow" and traversal.outcome == "deny"
    assert "args.path_traversal" in traversal.scan_rules
    assert by_id["delete-tool"].outcome == "require_approval"
    assert by_id["destructive-annotation"].outcome == "require_approval"
    assert by_id["rate-limit-burst"].outcome == "deny"  # 30 calls/60s, the burst sends more
    assert all(r.ok for r in results)  # attacks stopped, benign calls allowed


def test_permissive_policy_lets_attacks_through() -> None:
    results = run_cases(PolicyFile(scanner={"args_action": "off"}), BUILTIN_CASES)
    leaked = [r.case.id for r in results if not r.ok]
    assert "write-outside-sandbox" in leaked and "path-traversal" in leaked
    assert all(r.case.attack for r in results if not r.ok)  # benign calls still fine


def test_check_policy_command_reports_cases() -> None:
    r = runner.invoke(cli, ["check-policy", str(ROOT / "examples" / "policy.yaml")])
    assert r.exit_code == 0, r.output
    assert "✓ policy is valid" in r.output and "path-traversal" in r.output
    assert f"{len(BUILTIN_CASES)}/{len(BUILTIN_CASES)} cases as expected" in r.output


def test_check_policy_schema_error_exits_2(tmp_path: Path) -> None:
    bad = tmp_path / "policy.yaml"
    bad.write_text("version: 1\nrules:\n  - id: x\n    action: maybe\n")
    r = runner.invoke(cli, ["check-policy", str(bad)])
    assert r.exit_code == 2 and "policy.yaml:4: rules.0.action" in r.output


def test_check_policy_strict_fails_when_attack_gets_through(tmp_path: Path) -> None:
    lax = tmp_path / "policy.yaml"
    lax.write_text("version: 1\nscanner: {args_action: off}\n")
    assert runner.invoke(cli, ["check-policy", str(lax)]).exit_code == 0  # report only
    r = runner.invoke(cli, ["check-policy", str(lax), "--strict"])
    assert r.exit_code == 1 and "⚠" in r.output


def test_check_policy_user_fixtures(tmp_path: Path) -> None:
    cases = tmp_path / "cases.yaml"
    cases.write_text(
        "cases:\n"
        "  - {id: hosts, server: fs, tool: write_file, arguments: {path: /etc/hosts}, expect: deny}\n"
        "  - {id: wrong, server: fs, tool: read_file, arguments: {path: ./sandbox/a.md}, expect: deny}\n"
    )
    r = runner.invoke(
        cli, ["check-policy", str(ROOT / "examples" / "policy.yaml"), "--cases", str(cases), "--no-builtin"]
    )
    assert r.exit_code == 1, r.output
    assert "hosts" in r.output and "1/2 cases as expected" in r.output
    parsed = CaseFile.model_validate({"cases": [{"id": "a", "server": "s", "tool": "t", "expect": "allow"}]})
    assert parsed.cases[0].arguments == {}


# --------------------------------------------------------------------------- #22/#23 dashboard


@pytest.fixture(scope="module")
def seeded(tmp_path_factory: pytest.TempPathFactory) -> Path:
    db = tmp_path_factory.mktemp("polish") / "audit.db"
    seed(db, calls=200)
    return db


def full_app(db: Path, query: dict[str, str] | None = None) -> AppTest:
    os.environ["SHIELD_DB"] = str(db)
    at = AppTest.from_file(str(ROOT / "src" / "mcp_shield" / "dashboard" / "app.py"), default_timeout=30)
    for k, v in (query or {"range": "all"}).items():
        at.query_params[k] = v
    at.run()
    assert not at.exception, [e.value for e in at.exception]
    return at


def test_drilldown_targets() -> None:
    from mcp_shield.dashboard.pages import drilldown

    assert drilldown("blocked", "24h") == (
        "requests",
        {"range": "24h", "verdict": "block,denied,expired,error"},
    )
    assert drilldown("tokens", "7d") == ("requests", {"range": "7d", "sort": "tokens"})
    assert drilldown("overhead", "1h") == ("requests", {"range": "1h", "sort": "latency"})
    assert drilldown("cost", "24h") == ("tokens", {"range": "24h"})


def test_request_filters_read_from_url() -> None:
    from mcp_shield.dashboard.pages import filters_from_params

    f = filters_from_params(
        {"verdict": "block,denied,bogus", "sort": "tokens", "server": "fs", "q": "rm"}, ["(any)", "fs"]
    )
    assert f == {"server": "fs", "verdicts": ["block", "denied"], "order": "tokens", "text": "rm"}
    junk = filters_from_params({"sort": "nope", "server": "ghost"}, ["(any)", "fs"])
    assert junk == {"server": "(any)", "verdicts": [], "order": "newest", "text": ""}


def test_blocked_kpi_opens_filtered_requests(seeded: Path) -> None:
    at = full_app(seeded)
    at.button(key="kpi-blocked").click().run()
    assert not at.exception, [e.value for e in at.exception]
    assert at.title[0].value == "Requests"
    assert at.multiselect(key="verdicts").value == ["block", "denied", "expired", "error"]
    assert at.query_params["verdict"] == "block,denied,expired,error"


def test_tokens_kpi_sorts_by_tokens(seeded: Path) -> None:
    at = full_app(seeded)
    at.button(key="kpi-tokens").click().run()
    assert at.title[0].value == "Requests" and at.selectbox(key="order").value == "tokens"


def test_requests_filters_written_to_url(seeded: Path) -> None:
    at = full_app(seeded)
    at.button(key="kpi-requests").click().run()
    at.selectbox(key="server").select("fs").run()
    assert at.query_params["server"] == "fs"


def test_security_event_opens_its_request(seeded: Path) -> None:
    at = full_app(seeded)
    at.button(key="event-0").click().run()
    assert not at.exception, [e.value for e in at.exception]
    assert at.title[0].value == "Requests"
    assert at.query_params["id"].startswith("r_")
    assert any("Back to requests" in b.label for b in at.button)  # the detail view
