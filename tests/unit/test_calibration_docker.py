"""Gap #3 (Claude token counts + calibration) and gap #7 (container config and health check)."""

from __future__ import annotations

import math
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import anthropic
import httpx2
import pytest
from typer.testing import CliRunner

from mcp_shield import healthcheck
from mcp_shield.cli import app as cli
from mcp_shield.config import load_config
from mcp_shield.metering.calibrate import CORPUS, calibrate
from mcp_shield.metering.meter import Meter
from mcp_shield.metering.tokenizer import (
    AnthropicTokenizer,
    CharHeuristicTokenizer,
    ScaledTokenizer,
    make_tokenizer,
)

ROOT = Path(__file__).resolve().parents[2]


class FakeCountTokens:
    """Stands in for client.messages.count_tokens: ceil(len/3.3) + 7 tokens of request overhead."""

    def __init__(self, fail: bool = False):
        self.calls = 0
        self.fail = fail

    def count_tokens(self, *, model: str, messages: list[dict[str, Any]]) -> Any:
        self.calls += 1
        if self.fail:
            raise anthropic.APIConnectionError(request=httpx2.Request("POST", "https://api.anthropic.com"))
        text = messages[0]["content"]
        return type("Count", (), {"input_tokens": math.ceil(len(text) / 3.3) + 7})()


def fake_client(fail: bool = False) -> Any:
    return type("Client", (), {"messages": FakeCountTokens(fail)})()


# --------------------------------------------------------------------------- #3 tokenizers


def test_anthropic_tokenizer_subtracts_overhead_and_caches() -> None:
    client = fake_client()
    tok = AnthropicTokenizer("claude-opus-5-5", client=client)
    text = "x" * 330
    assert tok.name == "anthropic:claude-opus-5-5" and tok.remote is True
    assert tok.count(text) == 100  # 107 - (overhead 8 - 1)
    calls = client.messages.calls
    assert tok.count(text) == 100 and client.messages.calls == calls  # cache hit, no new request
    assert tok.count("") == 0


def test_anthropic_tokenizer_falls_back_when_api_fails() -> None:
    client = fake_client(fail=True)
    tok = AnthropicTokenizer(client=client, fallback=CharHeuristicTokenizer())
    assert tok.count("abcd" * 10) == 10  # char heuristic
    calls = client.messages.calls
    assert tok.count("efgh" * 10) == 10 and client.messages.calls == calls  # cooling down: no retry
    assert tok.fallbacks == 2 and not tok.disabled


def test_cache_is_bounded() -> None:
    tok = AnthropicTokenizer(client=fake_client(), cache_size=3)
    for i in range(5):
        tok.count(f"text {i}")
    assert len(tok._cache) == 3


def test_scaled_tokenizer() -> None:
    t = ScaledTokenizer(CharHeuristicTokenizer(), 1.2)
    assert t.name == "char:len/4*1.2" and t.count("a" * 400) == 120 and t.count("") == 0


def test_make_tokenizer_variants(monkeypatch: pytest.MonkeyPatch) -> None:
    assert make_tokenizer("char", scale=1.5).name == "char:len/4*1.5"
    # No credentials → the anthropic kind degrades to the (scaled) offline estimate instead of failing.
    for var in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_PROFILE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HOME", "/nonexistent")
    tok = make_tokenizer("anthropic", scale=1.2)
    assert isinstance(tok, AnthropicTokenizer) and tok.fallback.name.endswith("*1.2")
    first = tok.count("hello world")  # no credentials: counted by the scaled fallback
    assert first > 0 and tok.disabled and tok.fallbacks == 1
    tok.count("again")  # breaker open: no further API attempts
    assert tok.fallbacks == 2


@pytest.mark.anyio
async def test_meter_runs_remote_tokenizers_off_the_event_loop() -> None:
    seen: list[str] = []

    class Remote:
        name = "remote"
        remote = True

        def count(self, text: str) -> int:
            seen.append(threading.current_thread().name)
            return 5

    m = Meter(Remote())  # type: ignore[arg-type]
    assert await m.count_text("short") == 5
    assert seen and seen[0] != threading.main_thread().name


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


# --------------------------------------------------------------------------- #3 calibration


def test_calibration_scale_brings_estimate_within_10pct() -> None:
    reference = AnthropicTokenizer(client=fake_client())
    report = calibrate(reference, CharHeuristicTokenizer())
    assert report.reference == "anthropic:claude-opus-5-5" and report.estimator == "char:len/4"
    assert len(report.samples) == len(CORPUS)
    assert report.scale == pytest.approx(4 / 3.3, rel=0.02)  # the fake tokenizer's true ratio
    assert report.worst_before > 0.15 and report.within_10pct


def test_calibration_reports_failure_when_shapes_diverge() -> None:
    class Weird:
        name = "weird"

        def count(self, text: str) -> int:  # wildly inconsistent with the reference
            return 1 if "def " in text else len(text)

    report = calibrate(AnthropicTokenizer(client=fake_client()), Weird())
    assert not report.within_10pct


def test_calibrate_command_without_credentials_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_creds(model: str) -> Any:
        raise RuntimeError("Could not resolve authentication method")

    monkeypatch.setattr("mcp_shield.cli._reference_tokenizer", no_creds)
    r = CliRunner().invoke(cli, ["calibrate"])
    assert r.exit_code == 2 and "ant auth login" in r.output


def test_calibrate_command_prints_scale(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "mcp_shield.cli._reference_tokenizer", lambda model: AnthropicTokenizer(model, client=fake_client())
    )
    r = CliRunner().invoke(cli, ["calibrate"])
    assert r.exit_code == 0, r.output
    assert "PRD target ±10%" in r.output and "scale:" in r.output


def test_config_accepts_anthropic_tokenizer(tmp_path: Path) -> None:
    (tmp_path / "servers.yaml").write_text("servers:\n  - {id: a, transport: stdio, command: [x]}\n")
    (tmp_path / "shield.yaml").write_text(
        "policy: null\ntokenizer: {kind: anthropic, model: claude-opus-5-5, scale: 1.18}\n"
    )
    cfg = load_config(tmp_path / "shield.yaml", env={})
    assert cfg.shield.tokenizer.kind == "anthropic" and cfg.shield.tokenizer.scale == 1.18


# --------------------------------------------------------------------------- #7 container


def test_docker_example_config_is_valid() -> None:
    cfg = load_config(ROOT / "examples" / "docker" / "shield.yaml", env={"SHIELD_DATA": "/data"})
    assert cfg.shield.audit.db_path == "/data/shield-audit.db"
    assert [s.id for s in cfg.servers.servers] == ["notes", "evil"]
    assert all(s.command[0] == "python" for s in cfg.servers.servers)  # type: ignore[union-attr]


def test_compose_and_dockerfile_agree() -> None:
    import yaml

    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    assert set(compose["services"]) == {"shield", "dashboard", "demo"}
    shield_cmd = compose["services"]["shield"]["command"]
    assert "--allow-host" in shield_cmd and "shield:8765" in shield_cmd
    assert all(p.startswith("127.0.0.1:") for s in compose["services"].values() for p in s.get("ports", []))
    dockerfile = (ROOT / "Dockerfile").read_text()
    assert "uv sync --locked --no-dev" in dockerfile and "USER shield" in dockerfile
    assert "mcp_shield.healthcheck" in dockerfile


@pytest.mark.parametrize(("status", "expected"), [(401, 0), (200, 1), (500, 1)])
def test_healthcheck(status: int, expected: int) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            self.send_response(status)
            self.end_headers()

        def log_message(self, *args: Any) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.handle_request, daemon=True).start()
    try:
        assert healthcheck.main(f"http://127.0.0.1:{server.server_port}/mcp") == expected
    finally:
        server.server_close()


def test_healthcheck_unreachable() -> None:
    assert healthcheck.main("http://127.0.0.1:1/mcp") == 1
