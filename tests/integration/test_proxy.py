"""TS-A3: aggregation, namespacing, routing and upstream isolation, on both protocol revisions."""

from __future__ import annotations

from typing import Any

import pytest
from mcp import MCPError

from demo.benign_server import mcp as notes
from demo.misbehaving_servers import make_bad_names, make_broken_listing
from mcp_shield.pipeline.pipeline import SHIELD_META

pytestmark = pytest.mark.anyio


async def test_tools_are_aggregated_with_config_id_prefix(make_shield: Any, mode: str) -> None:
    async with make_shield({"notes": notes, "other": notes}, mode=mode) as (_, client):
        names = {t.name for t in (await client.list_tools()).tools}
    assert {"notes__echo", "notes__add", "other__echo"} <= names
    assert not any(n == "echo" for n in names)


async def test_call_is_routed_and_returns_upstream_result(make_shield: Any, mode: str) -> None:
    async with make_shield({"notes": notes}, mode=mode) as (shield, client):
        result = await client.call_tool("notes__add", {"a": 2, "b": 3})
    assert not result.is_error
    assert result.structured_content == {"result": 5}
    rows = shield.store.query("SELECT * FROM requests WHERE method='tools/call'")
    assert rows[0]["server_id"] == "notes" and rows[0]["tool"] == "notes__add"
    assert rows[0]["verdict"] == "allow"


async def test_unknown_tool_is_a_protocol_error_and_still_audited(make_shield: Any, mode: str) -> None:
    async with make_shield({"notes": notes}, mode=mode) as (shield, client):
        with pytest.raises(MCPError) as exc:
            await client.session.call_tool("notes__nope", {})
    assert exc.value.error.code == -32602
    row = shield.store.query("SELECT verdict, error_code FROM requests WHERE method='tools/call'")[0]
    assert row == {"verdict": "error", "error_code": -32602}


async def test_arguments_are_validated_against_upstream_schema(make_shield: Any, mode: str) -> None:
    async with make_shield({"notes": notes}, mode=mode) as (shield, client):
        result = await client.call_tool("notes__add", {"a": "two", "b": 3})
    assert result.is_error
    assert "[MCP Shield] Blocked" in result.content[0].text  # type: ignore[union-attr]
    assert result.meta and result.meta[SHIELD_META]["rule_ids"] == ["args.schema_invalid"]
    finding = shield.store.query("SELECT rule_id FROM findings")[0]
    assert finding["rule_id"] == "args.schema_invalid"


async def test_upstream_tool_error_passes_through_as_tool_error(make_shield: Any, mode: str) -> None:
    async with make_shield({"notes": notes}, mode=mode) as (_, client):
        result = await client.call_tool("notes__read_note", {"name": "missing"})
    assert result.is_error  # the upstream's own failure, not a gateway decision
    assert not (result.meta or {}).get(SHIELD_META)


async def test_down_upstream_does_not_break_the_others(make_shield: Any, mode: str) -> None:
    from mcp import StdioServerParameters

    dead = StdioServerParameters(command="/nonexistent/mcp-server")
    async with make_shield({"notes": notes, "dead": dead}, mode=mode, timeout_s=5) as (shield, client):
        names = {t.name for t in (await client.list_tools()).tools}
        result = await client.call_tool("notes__echo", {"text": "hi"})
    assert "notes__echo" in names and not any(n.startswith("dead__") for n in names)
    assert result.content[0].text == "hi"  # type: ignore[union-attr]
    up = shield.store.query("SELECT status, last_error FROM upstreams WHERE server_id='dead'")[0]
    assert up["status"] == "down" and up["last_error"]


async def test_unexposable_tool_names_are_dropped_per_tool(make_shield: Any, mode: str) -> None:
    async with make_shield({"notes": notes, "bad": make_bad_names()}, mode=mode) as (shield, client):
        names = {t.name for t in (await client.list_tools()).tools}
    assert "bad__ok" in names and "notes__echo" in names
    dropped = {d["name"]: d["reason"] for d in shield.pool.upstreams["bad"].dropped}
    assert set(dropped) == {"x" * 125, "has space!"}
    assert "max 128" in dropped["x" * 125]
    snap = shield.store.query("SELECT tool_count, dropped_tools FROM upstreams WHERE server_id='bad'")[0]
    assert snap["tool_count"] == 1 and "has space!" in snap["dropped_tools"]


async def test_schema_broken_upstream_is_isolated(make_shield: Any, mode: str) -> None:
    # SDK v2 rejects the whole listing, so the upstream is degraded - but nobody else is affected.
    async with make_shield({"notes": notes, "broken": make_broken_listing()}, mode=mode) as (shield, client):
        names = {t.name for t in (await client.list_tools()).tools}
        result = await client.call_tool("notes__echo", {"text": "still fine"})
    assert "notes__echo" in names and not any(n.startswith("broken__") for n in names)
    assert result.content[0].text == "still fine"  # type: ignore[union-attr]
    snap = shield.store.query("SELECT status, last_error FROM upstreams WHERE server_id='broken'")[0]
    assert snap["status"] == "degraded" and "invalid result" in snap["last_error"]


async def test_resources_and_prompts_are_proxied(make_shield: Any, mode: str) -> None:
    async with make_shield({"notes": notes}, mode=mode) as (_, client):
        resources = (await client.list_resources()).resources
        content = await client.read_resource("notes://welcome")
        prompts = (await client.list_prompts()).prompts
        prompt = await client.get_prompt("notes__summarize_note", {"name": "welcome"})
    assert [str(r.uri) for r in resources] == ["notes://welcome"]
    assert "Welcome to MCP Shield" in content.contents[0].text  # type: ignore[union-attr]
    assert [p.name for p in prompts] == ["notes__summarize_note"]
    assert "welcome" in prompt.messages[0].content.text  # type: ignore[union-attr]
