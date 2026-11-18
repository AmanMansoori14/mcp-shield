"""TS-C1..C5 query layer and export, on a deterministic seeded audit DB."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest

from demo.seed_audit import seed
from mcp_shield.audit import queries as q
from mcp_shield.audit.export import export_rows, to_csv, to_json
from mcp_shield.audit.store import AuditStore


@pytest.fixture(scope="module")
def store(tmp_path_factory: pytest.TempPathFactory) -> AuditStore:
    path = tmp_path_factory.mktemp("seed") / "audit.db"
    seed(path, calls=400)
    return AuditStore(path, read_only=True)


def test_seed_is_deterministic(tmp_path: Path) -> None:
    a = seed(tmp_path / "a.db", calls=150)
    b = seed(tmp_path / "b.db", calls=150)
    assert a == b
    sa, sb = AuditStore(tmp_path / "a.db"), AuditStore(tmp_path / "b.db")
    sql = "SELECT tool, verdict, total_tokens FROM requests r JOIN token_usage t ON t.request_id=r.id ORDER BY created_at"
    assert sa.query(sql) == sb.query(sql)


def test_since_iso() -> None:
    assert q.since_iso("all") is None
    assert q.since_iso("24h") is not None
    with pytest.raises(ValueError, match="unknown range"):
        q.since_iso("2w")


def test_overview_matches_raw_sql(store: AuditStore) -> None:
    o = q.overview(store, None)
    assert o["requests"] == store.scalar("SELECT COUNT(*) FROM requests")
    assert o["total_tokens"] == store.scalar("SELECT SUM(total_tokens) FROM token_usage")
    assert o["blocked"] == store.scalar(
        "SELECT COUNT(*) FROM requests WHERE verdict IN ('block','denied','error','expired')"
    )
    assert 0 < o["blocked_pct"] < 100 and o["p95_overhead_ms"] > 0
    assert q.overview(store, "2099-01-01")["requests"] == 0


def test_list_requests_filters_and_pagination(store: AuditStore) -> None:
    rows, total = q.list_requests(store, q.Filters(server_id="fs", limit=10))
    assert total == store.scalar("SELECT COUNT(*) FROM requests WHERE server_id='fs'")
    assert len(rows) == 10 and {r["server_id"] for r in rows} == {"fs"}
    page2, _ = q.list_requests(store, q.Filters(server_id="fs", limit=10, offset=10))
    assert not {r["id"] for r in rows} & {r["id"] for r in page2}

    blocked, n = q.list_requests(store, q.Filters(verdicts=["block"]))
    assert n > 0 and {r["verdict"] for r in blocked} == {"block"}

    _, n_rule = q.list_requests(store, q.Filters(text="path_traversal"))
    assert n_rule == store.scalar("SELECT COUNT(*) FROM findings WHERE rule_id='args.path_traversal'")

    biggest, _ = q.list_requests(store, q.Filters(order="tokens", limit=3))
    assert biggest[0]["total_tokens"] >= biggest[1]["total_tokens"] >= biggest[2]["total_tokens"]


def test_filters_never_interpolate_input(store: AuditStore) -> None:
    _, total = q.list_requests(store, q.Filters(text="'; DROP TABLE requests; --"))
    assert total == 0
    assert store.scalar("SELECT COUNT(*) FROM requests") > 0


def test_get_request_includes_legs_findings_and_policy(store: AuditStore) -> None:
    rid = store.scalar("SELECT id FROM requests WHERE tool='github__merge_pull_request' AND leg=2 LIMIT 1")
    r = q.get_request(store, rid)
    assert r is not None
    assert [leg["leg"] for leg in r["legs"]] == [1, 2] and r["legs"][0]["verdict"] == "approval_pending"
    assert r["connection"]["client_name"] in ("claude-desktop", "claude-code", "cursor")
    assert r["policy"]["hash"].startswith("p_")
    assert q.get_request(store, "r_missing") is None


def test_token_usage_groupings(store: AuditStore) -> None:
    by_tool = q.token_usage(store, None, "tool", 50)
    assert by_tool[0]["total_tokens"] >= by_tool[-1]["total_tokens"]
    assert sum(r["calls"] for r in by_tool) == store.scalar(
        "SELECT COUNT(*) FROM requests WHERE method='tools/call'"
    )
    by_method = q.token_usage(store, None, "method")
    assert {r["key"] for r in by_method} == {"tools/call", "tools/list"}
    with pytest.raises(ValueError):
        q.token_usage(store, None, "planet")


def test_security_events_respect_min_severity(store: AuditStore) -> None:
    high = q.security_events(store, None, "high")
    assert {e["severity"] for e in high} <= {"high", "critical"}
    low = q.security_events(store, None, "low")
    assert len(low) >= len(high)
    assert all(e["latest_request_id"].startswith("r_") for e in high)


def test_upstreams_pins_policy_budget(store: AuditStore) -> None:
    assert {u["server_id"] for u in q.upstreams(store)} == {"notes", "github", "fs", "evil"}
    assert any(p["status"] == "hidden" for p in q.tool_pins(store))
    assert q.current_policy(store) is not None
    for b in q.budget_breaches(store, None):
        assert b["response_tokens"] > 4000


def test_export_csv_and_json(store: AuditStore) -> None:
    rows = export_rows(store, q.Filters(), batch=97)  # odd batch size exercises paging
    assert len(rows) == store.scalar("SELECT COUNT(*) FROM requests")
    assert "params_redacted" not in rows[0]  # payloads are opt-in
    parsed = list(csv.DictReader(io.StringIO(to_csv(rows))))
    assert len(parsed) == len(rows) and "rule_ids" in parsed[0] and "total_tokens" in parsed[0]
    doc = json.loads(to_json(rows))
    assert doc["tokens_are_estimates"] is True and doc["count"] == len(rows)
    with_payloads = export_rows(store, q.Filters(verdicts=["warn"]), payloads=True)
    assert "params_redacted" in with_payloads[0]
    assert to_csv([]).startswith("id,created_at")
