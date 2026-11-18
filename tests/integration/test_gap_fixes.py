"""Fixes for PRD gaps #9 (redaction of resources/prompts), #17 (upstream reconnect),
#20 (audit every protocol message) and one connection row per client."""

from __future__ import annotations

import sys
from typing import Any

import anyio
import pytest
from mcp import Client, StdioServerParameters, types

from demo.benign_server import mcp as notes
from demo.poisoned_server import mcp as evil

pytestmark = pytest.mark.anyio


# --------------------------------------------------------------------------- #9


async def test_resource_and_prompt_replies_are_redacted(make_shield: Any, mode: str) -> None:
    async with make_shield({"evil": evil}, mode=mode) as (shield, client):
        res = await client.read_resource("evil://config")
        prompt = await client.get_prompt("evil__leaky_prompt", {})
    text = res.contents[0].text  # type: ignore[union-attr]
    assert "AKIAIOSFODNN7EXAMPLE" not in text and "[REDACTED:aws_access_key]" in text
    assert "ops@example.com" not in text
    ptext = prompt.messages[0].content.text  # type: ignore[union-attr]
    assert "ghp_" + "a" * 36 not in ptext and "[REDACTED:github_token]" in ptext
    rows = shield.store.query(
        "SELECT r.method, r.verdict, f.rule_id FROM requests r JOIN findings f ON f.request_id = r.id "
        "WHERE r.method IN ('resources/read', 'prompts/get')"
    )
    assert {(r["method"], r["rule_id"]) for r in rows} >= {
        ("resources/read", "redaction.aws_access_key"),
        ("prompts/get", "redaction.github_token"),
    }
    assert {r["verdict"] for r in rows} == {"warn"}


# --------------------------------------------------------------------------- #20 and connections


async def test_every_protocol_message_is_audited(make_shield: Any, mode: str) -> None:
    async with make_shield({"notes": notes}, mode=mode) as (shield, client):
        await client.call_tool("notes__echo", {"text": "x"})
        legacy = client.protocol_version < "2026-07-28"
        if legacy:
            with pytest.warns(Warning):
                await client.send_ping()
    methods = {r["method"] for r in shield.store.query("SELECT method FROM requests")}
    if legacy:
        assert {"initialize", "notifications/initialized", "ping", "tools/call"} <= methods
    else:
        assert {"server/discover", "tools/call"} <= methods


async def test_one_connection_row_per_client(make_shield: Any, mode: str) -> None:
    async with make_shield({"notes": notes}, mode=mode) as (shield, client):
        for i in range(5):
            await client.call_tool("notes__echo", {"text": str(i)})
        await client.list_tools()
    assert shield.store.scalar("SELECT COUNT(*) FROM connections") == 1
    conn = shield.store.query("SELECT client_name FROM connections")[0]
    assert conn["client_name"] == "mcp"  # the SDK client's default name, from clientInfo


async def test_list_changed_is_pushed_to_legacy_clients(make_shield: Any) -> None:
    received: list[str] = []

    async def on_message(message: Any) -> None:
        if isinstance(message, types.ToolListChangedNotification):
            received.append(message.method)

    async with (
        make_shield({"notes": notes}) as (shield, _),
        Client(shield.server, mode="legacy", message_handler=on_message) as client,  # type: ignore[arg-type]
    ):
        await client.list_tools()
        await shield.pool._on_list_changed("notes", "tools")
        with anyio.fail_after(5):
            while not received:  # noqa: ASYNC110 - waiting on a callback the SDK drives
                await anyio.sleep(0.01)
    assert received == ["notifications/tools/list_changed"]


# --------------------------------------------------------------------------- #17


async def test_crashed_upstream_reconnects(make_shield: Any) -> None:
    crashy = StdioServerParameters(command=sys.executable, args=["-m", "demo.crashy_server"])
    async with make_shield({"crashy": crashy}, timeout_s=20, restart_backoff_s=0.2) as (shield, client):
        assert (await client.call_tool("crashy__echo", {"text": "before"})).content[0].text == "before"  # type: ignore[union-attr]
        await client.call_tool("crashy__crash", {})
        await anyio.sleep(0.6)  # the process exits 0.2s after answering
        lost = await client.call_tool("crashy__echo", {"text": "during"})
        assert lost.is_error and "reconnecting" in lost.content[0].text  # type: ignore[union-attr]
        up = shield.pool.upstreams["crashy"]
        with anyio.fail_after(20):
            while up.restarts == 0 or up.status != "up":  # noqa: ASYNC110 - polling pool state
                await anyio.sleep(0.05)
        after = await client.call_tool("crashy__echo", {"text": "after"})
    assert after.content[0].text == "after"  # type: ignore[union-attr]
    assert up.restarts >= 1


async def test_gives_up_after_max_restarts(make_shield: Any) -> None:
    dead = StdioServerParameters(command="/nonexistent/mcp-server")
    async with make_shield({"notes": notes, "dead": dead}, restart_backoff_s=0.05, max_restarts=3) as (
        shield,
        client,
    ):
        up = shield.pool.upstreams["dead"]
        with anyio.fail_after(10):
            while up.restarts < 2:  # noqa: ASYNC110 - polling pool state
                await anyio.sleep(0.02)
        await anyio.sleep(0.5)  # well past the remaining backoff
        assert up.restarts == 2 and up.status == "down"  # 3 failed attempts in total, then stop
        ok = await client.call_tool("notes__echo", {"text": "others fine"})
    assert ok.content[0].text == "others fine"  # type: ignore[union-attr]
