"""TS-C9 OpenTelemetry attributes, TS-C1..C4 dashboard pages, retention and the CLI."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from streamlit.testing.v1 import AppTest
from typer.testing import CliRunner

from demo.benign_server import mcp as notes
from demo.seed_audit import seed
from mcp_shield.audit.models import AuditRecord, ConnectionRecord, TokenRecord
from mcp_shield.cli import app as cli

EXPORTER = InMemorySpanExporter()
_provider = TracerProvider()
_provider.add_span_processor(SimpleSpanProcessor(EXPORTER))
trace.set_tracer_provider(_provider)


# --------------------------------------------------------------------------- OpenTelemetry


@pytest.mark.anyio
async def test_spans_carry_shield_decision(make_shield: Any) -> None:
    EXPORTER.clear()
    async with make_shield({"notes": notes}) as (_, client):
        await client.call_tool("notes__echo", {"text": "traced"})
        await client.call_tool("notes__echo", {"text": "../../etc/passwd"})
    spans = [
        s
        for s in EXPORTER.get_finished_spans()
        if s.name.startswith("tools/call") and (s.attributes or {}).get("shield.verdict")
    ]
    by_verdict = {s.attributes["shield.verdict"]: s for s in spans}  # type: ignore[index]
    ok, blocked = by_verdict["allow"], by_verdict["block"]
    assert ok.name.startswith("tools/call") and ok.attributes["shield.server_id"] == "notes"  # type: ignore[index]
    assert ok.attributes["shield.tokens.total"] > 0 and ok.attributes["shield.tokens.estimated"] is True  # type: ignore[index]
    assert "args.path_traversal" in blocked.attributes["shield.rule_ids"]  # type: ignore[index,operator]
    assert any(e.name == "shield.denied" for e in blocked.events)


# --------------------------------------------------------------------------- dashboard

PAGES = ["page_overview", "page_requests", "page_tokens", "page_security", "page_upstreams"]


def run_page(page: str, db: Path, query: dict[str, str] | None = None) -> AppTest:
    os.environ["SHIELD_DB"] = str(db)
    params = "".join(f"st.query_params[{k!r}] = {v!r}\n" for k, v in (query or {"range": "all"}).items())
    at = AppTest.from_string(
        f"import streamlit as st\nfrom mcp_shield.dashboard import pages\npages.store.clear()\n{params}pages.{page}()\n",
        default_timeout=30,
    )
    at.run()
    return at


@pytest.fixture(scope="module")
def seeded(tmp_path_factory: pytest.TempPathFactory) -> Path:
    db = tmp_path_factory.mktemp("dash") / "audit.db"
    seed(db, calls=300)
    return db


@pytest.mark.parametrize("page", PAGES)
def test_dashboard_pages_render(seeded: Path, page: str) -> None:
    at = run_page(page, seeded)
    assert not at.exception, [e.value for e in at.exception]
    assert at.title[0].value  # every page has its heading


def test_overview_kpis(seeded: Path) -> None:
    at = run_page("page_overview", seeded)
    metrics = {m.label: m.value for m in at.metric}
    assert int(metrics["Requests"].replace(",", "")) > 300
    assert "Tokens (estimated)" in metrics and metrics["p95 Shield overhead"].endswith("ms")


def test_request_detail_and_missing(seeded: Path) -> None:
    from mcp_shield.audit.store import AuditStore

    rid = AuditStore(seeded, read_only=True).scalar("SELECT id FROM requests WHERE verdict='block' LIMIT 1")
    at = run_page("page_requests", seeded, {"range": "all", "id": rid})
    assert not at.exception
    assert any("Reason" in m.value for m in at.markdown)
    gone = run_page("page_requests", seeded, {"range": "all", "id": "r_nope"})
    assert any("not found" in w.value for w in gone.warning)


def test_requests_filters(seeded: Path) -> None:
    at = run_page("page_requests", seeded)
    at.selectbox(key="server").select("fs").run()
    assert not at.exception
    assert at.caption[0].value.endswith("tokens are estimates")


def test_dashboard_empty_state(tmp_path: Path) -> None:
    at = run_page("page_overview", tmp_path / "missing.db")
    assert any("not found" in e.value for e in at.error)


# --------------------------------------------------------------------------- retention


@pytest.mark.anyio
async def test_retention_prunes_old_rows(make_shield: Any) -> None:
    async with make_shield({"notes": notes}) as (shield, client):
        old = AuditRecord(
            connection=ConnectionRecord(id="c_old", kind="stdio"),
            method="tools/call",
            verdict="allow",
            latency_ms=1.0,
            shield_version="0.1.0",
            created_at="2020-01-01T00:00:00.000+00:00",
            tokens=TokenRecord(tokenizer="x"),
        )
        shield.store.write(old)
        await client.call_tool("notes__echo", {"text": "fresh"})
        await shield.audit.flush()
        removed = await shield.prune()
    assert removed == 1
    assert shield.store.scalar("SELECT COUNT(*) FROM requests WHERE created_at < '2021-01-01'") == 0
    assert shield.store.scalar("SELECT COUNT(*) FROM requests WHERE method='tools/call'") == 1


# --------------------------------------------------------------------------- CLI


@pytest.fixture
def cfg_dir(tmp_path: Path) -> Path:
    seed(tmp_path / "audit.db", calls=120)
    (tmp_path / "servers.yaml").write_text("servers:\n  - {id: notes, transport: stdio, command: [x]}\n")
    (tmp_path / "shield.yaml").write_text("policy: null\naudit: {db_path: audit.db, retention_days: 30}\n")
    return tmp_path


def test_cli_check_stats_export_prune(cfg_dir: Path) -> None:
    runner = CliRunner()
    cfg = str(cfg_dir / "shield.yaml")
    check = runner.invoke(cli, ["check", "-c", cfg])
    assert check.exit_code == 0 and "is valid" in check.output
    stats = runner.invoke(cli, ["stats", "-c", cfg])
    assert stats.exit_code == 0 and "Security events" in stats.output
    out = cfg_dir / "out.json"
    exp = runner.invoke(cli, ["export", "-c", cfg, "--since", "all", "--format", "json", "--out", str(out)])
    assert exp.exit_code == 0
    assert json.loads(out.read_text())["count"] > 120
    csv_out = runner.invoke(cli, ["export", "-c", cfg, "--since", "all"])
    assert csv_out.output.startswith("id,created_at")
    prune = runner.invoke(cli, ["prune", "-c", cfg])
    assert prune.exit_code == 0 and "pruned" in prune.output  # seeded data is dated 2026-11-10..16


def test_cli_http_requires_token(cfg_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SHIELD_TOKEN", raising=False)
    r = CliRunner().invoke(cli, ["run", "--http", "-c", str(cfg_dir / "shield.yaml")])
    assert r.exit_code == 2 and "SHIELD_TOKEN" in r.output


def test_cli_bad_config_exits_2(tmp_path: Path) -> None:
    (tmp_path / "shield.yaml").write_text("servers: missing.yaml\n")
    r = CliRunner().invoke(cli, ["check", "-c", str(tmp_path / "shield.yaml")])
    assert r.exit_code == 2 and "cannot read file" in r.output
