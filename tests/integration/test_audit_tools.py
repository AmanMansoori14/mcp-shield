"""TS-C8: the read-only shield_* MCP tools, plus the evaluation answer key."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from demo.benign_server import mcp as notes
from demo.seed_audit import seed
from mcp_shield.audit.store import AuditStore
from mcp_shield.proxy.audit_tools import NAMES, AuditTools

pytestmark = pytest.mark.anyio
EVAL = Path(__file__).resolve().parents[2] / "evals" / "shield_tools_eval.xml"


async def test_tools_are_listed_read_only(make_shield: Any, mode: str) -> None:
    async with make_shield({"notes": notes}, mode=mode) as (_, client):
        tools = {t.name: t for t in (await client.list_tools()).tools}
    assert set(tools) >= NAMES
    for name in NAMES:
        t = tools[name]
        assert t.annotations and t.annotations.read_only_hint and not t.annotations.destructive_hint
        assert t.output_schema and t.input_schema["additionalProperties"] is False


async def test_list_requests_markdown_json_and_pagination(make_shield: Any, mode: str) -> None:
    async with make_shield({"notes": notes}, mode=mode) as (shield, client):
        for i in range(7):
            await client.call_tool("notes__echo", {"text": str(i)})
        md = await client.call_tool("shield_list_requests", {"tool": "notes__echo", "limit": 3})
        page1 = await client.call_tool(
            "shield_list_requests", {"tool": "notes__echo", "limit": 3, "response_format": "json"}
        )
        cursor = page1.structured_content["page"]["next_cursor"]  # type: ignore[index]
        page2 = await client.call_tool(
            "shield_list_requests",
            {"tool": "notes__echo", "limit": 3, "cursor": cursor, "response_format": "json"},
        )
    text = md.content[0].text  # type: ignore[union-attr]
    assert "**7 requests**" in text and "| notes__echo | allow |" in text and 'cursor: "o:3"' in text
    p1, p2 = page1.structured_content, page2.structured_content
    assert p1 and p2 and p1["page"] == {"total": 7, "count": 3, "has_more": True, "next_cursor": "o:3"}
    assert json.loads(page1.content[0].text) == p1  # type: ignore[union-attr]
    assert not {r["id"] for r in p1["requests"]} & {r["id"] for r in p2["requests"]}
    # The audit tools are audited too, under the "shield" server.
    assert shield.store.scalar("SELECT COUNT(*) FROM requests WHERE server_id='shield'") == 3


async def test_actionable_errors(make_shield: Any) -> None:
    async with make_shield({"notes": notes}) as (_, client):
        bad_cursor = await client.call_tool("shield_list_requests", {"cursor": "page-2"})
        bad_since = await client.call_tool("shield_get_token_usage", {"since": "fortnight"})
    assert bad_cursor.is_error and "pass the next_cursor value" in bad_cursor.content[0].text  # type: ignore[union-attr]
    # Rejected by Shield's schema validation before the tool runs, with the allowed values listed.
    assert bad_since.is_error and "fortnight" in bad_since.content[0].text  # type: ignore[union-attr]


async def test_token_usage_and_events(make_shield: Any) -> None:
    async with make_shield({"notes": notes}) as (_, client):
        await client.call_tool("notes__read_note", {"name": "big"})
        await client.call_tool("notes__echo", {"text": "../../etc/passwd"})  # blocked, high severity
        usage = await client.call_tool(
            "shield_get_token_usage", {"group_by": "tool", "response_format": "json"}
        )
        events = await client.call_tool("shield_list_security_events", {"min_severity": "high"})
    rows = usage.structured_content["rows"]  # type: ignore[index]
    assert rows[0]["key"] == "notes__read_note" and usage.structured_content["estimated"] is True  # type: ignore[index]
    assert "args.path_traversal" in events.content[0].text  # type: ignore[union-attr]


async def test_eval_answers_are_correct(tmp_path: Path) -> None:
    """Every answer in evals/shield_tools_eval.xml is reachable through the shield_* tools."""
    db = tmp_path / "eval.db"
    seed(db, calls=2000, seed_value=42)
    tools = AuditTools(AuditStore(db, read_only=True))
    answers = re.findall(r"<answer>(.*?)</answer>", EVAL.read_text())
    assert len(answers) == 10

    async def call(name: str, **args: Any) -> Any:
        r = await tools.call(name, {"since": "all", "response_format": "json", **args})
        assert not r.is_error, r.content
        return r.structured_content

    by_tool = (await call("shield_get_token_usage", group_by="tool", limit=50))["rows"]
    by_server = (await call("shield_get_token_usage", group_by="server"))["rows"]
    events = (await call("shield_list_security_events", min_severity="low", limit=50))["events"]
    denied = (await call("shield_list_requests", tool="github__merge_pull_request", verdict="denied"))["page"]
    approved = (await call("shield_list_requests", tool="github__merge_pull_request", verdict="approved"))[
        "page"
    ]
    list_prs = (await call("shield_list_requests", tool="github__list_prs"))["page"]
    warned = (await call("shield_list_requests", verdict="warn"))["page"]
    upstream = [r for r in by_server if r["key"] in ("notes", "github", "fs", "evil")]

    computed = [
        max(by_tool, key=lambda r: r["response_tokens"])["key"],
        by_server[0]["key"],
        str(next(e["count"] for e in events if e["rule_id"] == "args.path_traversal")),
        str(denied["total"]),
        str(approved["total"]),
        str(round(next(r["avg_response_tokens"] for r in by_tool if r["key"] == "github__list_prs"))),
        next(e["rule_id"] for e in events if e["severity"] in ("high", "critical")),
        str(list_prs["total"]),
        min(upstream, key=lambda r: r["total_tokens"])["key"],
        str(warned["total"]),
    ]
    assert computed == answers
