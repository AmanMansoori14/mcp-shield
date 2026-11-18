"""TS-A4: the IP-A11 pass-through matrix."""

from __future__ import annotations

from typing import Any

import pytest
from mcp import Client

from demo.benign_server import mcp as notes
from demo.misbehaving_servers import asks_user

pytestmark = pytest.mark.anyio


async def test_progress_from_upstream_reaches_the_client(make_shield: Any, mode: str) -> None:
    seen: list[float] = []

    async def on_progress(progress: float, total: float | None, message: str | None) -> None:
        seen.append(progress)

    async with make_shield({"notes": notes}, mode=mode) as (_, client):
        result = await client.call_tool("notes__slow_count", {"to": 5}, progress_callback=on_progress)
    assert result.content[0].text == "counted to 5"  # type: ignore[union-attr]
    assert seen == [1, 2, 3, 4, 5]


async def test_ping_is_answered_locally_for_legacy_clients(make_shield: Any) -> None:
    async with make_shield({"notes": notes}, mode="legacy") as (shield, client):
        with pytest.warns(Warning):  # ping is removed in 2026-07-28; the SDK warns on use
            await client.send_ping()
    # Answered by Shield itself: nothing was forwarded or audited as an upstream call.
    assert shield.store.scalar("SELECT COUNT(*) FROM requests WHERE method='ping'") == 0


async def test_upstream_elicitation_is_refused_and_recorded(make_shield: Any, mode: str) -> None:
    async with make_shield({"ask": asks_user}, mode=mode) as (shield, client):
        result = await client.call_tool("ask__needs_confirmation", {})
    # The upstream never gets a "yes": either it falls back, or the call fails - never "confirmed".
    text = " ".join(getattr(c, "text", "") for c in result.content)
    assert "confirmed" not in text.replace("not confirmed", "")
    rules = [r["rule_id"] for r in shield.store.query("SELECT rule_id FROM findings")]
    assert "passthrough.backchannel_refused" in rules


async def test_list_changed_refreshes_and_updates_snapshot(make_shield: Any) -> None:
    from mcp.server import MCPServer

    dyn = MCPServer("dyn")

    @dyn.tool()
    def first() -> str:
        """The first tool."""
        return "1"

    async with make_shield({"dyn": dyn}) as (shield, client):
        before = {t.name for t in (await client.list_tools()).tools}

        @dyn.tool()
        def second() -> str:
            """Added at runtime."""
            return "2"

        await shield.pool._on_list_changed("dyn", "tools")
        after = {t.name for t in (await client.list_tools()).tools}
    assert before == {"dyn__first"}
    assert after == {"dyn__first", "dyn__second"}
    assert shield.store.scalar("SELECT tool_count FROM upstreams WHERE server_id='dyn'") == 2


async def test_shield_works_over_a_real_stdio_subprocess(make_shield: Any) -> None:
    """End-to-end over a real stdio upstream (the way servers.yaml launches them)."""
    import sys

    from mcp import StdioServerParameters

    params = StdioServerParameters(command=sys.executable, args=["-m", "demo.benign_server"])
    async with make_shield({"notes": params}, timeout_s=30) as (_, client):
        assert isinstance(client, Client)
        result = await client.call_tool("notes__echo", {"text": "over stdio"})
    assert result.content[0].text == "over stdio"  # type: ignore[union-attr]
