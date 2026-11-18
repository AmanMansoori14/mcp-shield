"""TS-A5/A6/A7 end to end: every request audited with tokens and stage timings; fail-closed."""

from __future__ import annotations

import json
from typing import Any

import pytest
from mcp import MCPError, types

from demo.benign_server import mcp as notes
from mcp_shield.pipeline.context import RequestContext

pytestmark = pytest.mark.anyio


async def test_every_request_has_exactly_one_audit_row(make_shield: Any, mode: str) -> None:
    """1,000 mixed requests (ok, upstream errors, gateway blocks, unknown tools) → 1,000 rows."""
    sent = 0
    async with make_shield({"notes": notes}, mode=mode) as (shield, client):
        for i in range(250):
            await client.call_tool("notes__echo", {"text": f"hello {i}"})
            await client.call_tool("notes__read_note", {"name": "missing"})  # upstream tool error
            await client.call_tool("notes__add", {"a": "x", "b": 1})  # blocked: schema
            with pytest.raises(MCPError):
                await client.session.call_tool("notes__ghost", {})  # unknown tool
            sent += 4
    calls = shield.store.scalar("SELECT COUNT(*) FROM requests WHERE method='tools/call'")
    assert calls == sent == 1000
    rows = shield.store.query(
        "SELECT verdict, COUNT(*) AS n FROM requests WHERE method='tools/call' GROUP BY verdict"
    )
    by_verdict = {r["verdict"]: r["n"] for r in rows}
    assert by_verdict == {"allow": 500, "block": 250, "error": 250}
    assert shield.store.scalar("SELECT COUNT(*) FROM token_usage") == shield.store.scalar(
        "SELECT COUNT(*) FROM requests"
    )


async def test_tokens_are_recorded_per_request(make_shield: Any) -> None:
    async with make_shield({"notes": notes}) as (shield, client):
        await client.list_tools()
        await client.call_tool("notes__read_note", {"name": "big"})
    listing = shield.store.query(
        "SELECT t.* FROM token_usage t JOIN requests r ON r.id=t.request_id WHERE r.method='tools/list'"
    )[0]
    assert listing["schema_tokens"] > 0 and listing["response_tokens"] == 0
    call = shield.store.query(
        "SELECT t.* FROM token_usage t JOIN requests r ON r.id=t.request_id WHERE r.method='tools/call'"
    )[0]
    big_text_tokens = (
        len(" ".join(["Token-heavy tool output can quietly eat your context window."] * 400)) // 4
    )
    assert abs(call["response_tokens"] - big_text_tokens) <= 2
    assert call["request_tokens"] > 0 and call["estimated"] == 1 and call["tokenizer"] == "char:len/4"
    assert call["total_tokens"] == call["request_tokens"] + call["response_tokens"]


async def test_blocked_calls_cost_no_response_tokens(make_shield: Any) -> None:
    async with make_shield({"notes": notes}) as (shield, client):
        await client.call_tool("notes__add", {"a": "x", "b": 1})
    row = shield.store.query(
        "SELECT t.request_tokens, t.response_tokens FROM token_usage t "
        "JOIN requests r ON r.id=t.request_id WHERE r.method='tools/call'"
    )[0]
    assert row["request_tokens"] > 0 and row["response_tokens"] == 0


async def test_stage_timings_and_connection_are_recorded(make_shield: Any, mode: str) -> None:
    async with make_shield({"notes": notes}, mode=mode) as (shield, client):
        await client.call_tool("notes__echo", {"text": "t"})
        negotiated = client.protocol_version
    row = shield.store.query("SELECT * FROM requests WHERE method='tools/call'")[0]
    stages = json.loads(row["stage_ms"])
    assert {"meter.request", "upstream", "meter.response"} <= set(stages)
    assert row["latency_ms"] >= stages["upstream"] and row["upstream_ms"] == stages["upstream"]
    assert row["protocol_version"] == negotiated
    conn = shield.store.query("SELECT * FROM connections")[0]
    assert conn["kind"] == "in_process" and conn["protocol_version"] == negotiated
    assert conn["client_name"] is not None
    assert row["policy_hash"] == "p_test" and row["shield_version"] == "0.1.0"


async def test_payloads_are_not_stored_until_redaction_exists(make_shield: Any) -> None:
    async with make_shield({"notes": notes}) as (shield, client):
        await client.call_tool("notes__echo", {"text": "AKIAIOSFODNN7EXAMPLE"})
    row = shield.store.query(
        "SELECT params_redacted, result_redacted FROM requests WHERE method='tools/call'"
    )[0]
    assert row == {"params_redacted": None, "result_redacted": None}  # MP-C3


async def test_internal_failure_fails_closed(make_shield: Any) -> None:
    class Exploding:
        name = "exploding"

        async def __call__(self, ctx: RequestContext) -> None:
            raise RuntimeError("bug in a stage")

    forwarded: list[str] = []

    async with make_shield({"notes": notes}) as (shield, client):
        shield.pipeline.pre_stages.append(Exploding())
        original = shield.pool.upstreams["notes"].client.call_tool  # type: ignore[union-attr]

        async def spy(*a: Any, **k: Any) -> types.CallToolResult:
            forwarded.append(a[0])
            return await original(*a, **k)

        shield.pool.upstreams["notes"].client.call_tool = spy  # type: ignore[union-attr,method-assign]
        result = await client.call_tool("notes__echo", {"text": "hi"})
    assert result.is_error and "Blocked (error)" in result.content[0].text  # type: ignore[union-attr]
    assert forwarded == []  # nothing reached the upstream (MP-C5)
    row = shield.store.query("SELECT verdict FROM requests WHERE method='tools/call'")[0]
    assert row["verdict"] == "error"
    assert shield.store.scalar("SELECT rule_id FROM findings") == "internal.error"


async def test_blocking_pre_stage_stops_the_call(make_shield: Any) -> None:
    class DenyAll:
        name = "policy"

        async def __call__(self, ctx: RequestContext) -> None:
            ctx.escalate("block", "denied by rule test-deny")

    async with make_shield({"notes": notes}) as (shield, client):
        shield.pipeline.pre_stages.append(DenyAll())
        result = await client.call_tool("notes__echo", {"text": "hi"})
    assert result.is_error
    assert "Blocked: denied by rule test-deny" in result.content[0].text  # type: ignore[union-attr]
    stages = json.loads(shield.store.scalar("SELECT stage_ms FROM requests WHERE method='tools/call'"))
    assert "policy" in stages and "upstream" not in stages


async def test_overhead_is_small(make_shield: Any) -> None:
    """p95 Shield overhead (total latency minus upstream time) stays well under the 25 ms target."""
    async with make_shield({"notes": notes}) as (shield, client):
        for i in range(200):
            await client.call_tool("notes__echo", {"text": str(i)})
    rows = shield.store.query(
        "SELECT latency_ms - upstream_ms AS overhead FROM requests "
        "WHERE method='tools/call' ORDER BY overhead"
    )
    p95 = rows[int(len(rows) * 0.95)]["overhead"]
    assert p95 < 25, f"p95 overhead {p95:.2f} ms"
