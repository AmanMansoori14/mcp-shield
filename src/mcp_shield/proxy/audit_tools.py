"""Read-only ``shield_*`` MCP tools: let the agent ask about its own audit (TS-C8, MP-B7).

Built to the mcp-builder conventions: service-prefixed snake_case names, read-only
annotations, ``limit`` + ``cursor`` pagination with ``has_more``, a ``response_format``
switch (markdown for people, json for programs), an ``outputSchema`` with matching
``structuredContent``, and errors that say what to try next.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any

import anyio.to_thread
from mcp import types

from mcp_shield.audit.queries import (
    RANGES,
    SEVERITY_RANK,
    Filters,
    list_requests,
    security_events,
    since_iso,
    token_usage,
)
from mcp_shield.audit.store import AuditStore

READ_ONLY = types.ToolAnnotations(
    read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False
)
_SINCE = {
    "type": "string",
    "enum": list(RANGES),
    "default": "24h",
    "description": "Time window: 15m, 1h, 24h, 7d, 30d or all.",
}
_FORMAT = {
    "type": "string",
    "enum": ["markdown", "json"],
    "default": "markdown",
    "description": "markdown for reading, json for further processing.",
}
_LIMIT = {
    "type": "integer",
    "minimum": 1,
    "maximum": 100,
    "default": 20,
    "description": "Max items to return (1-100).",
}
_PAGE = {
    "type": "object",
    "properties": {
        "total": {"type": "integer"},
        "count": {"type": "integer"},
        "has_more": {"type": "boolean"},
        "next_cursor": {"type": ["string", "null"]},
    },
}

TOOLS: list[types.Tool] = [
    types.Tool(
        name="shield_list_requests",
        title="List audited MCP requests",
        description=(
            "List MCP requests that went through MCP Shield, newest first, with verdict, latency and estimated "
            "token usage. Filter by server, tool or verdict. Use for questions like 'what did the agent call?' "
            "or 'which calls were blocked?'."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "since": _SINCE,
                "server": {"type": "string", "description": "Upstream server id, e.g. 'github'."},
                "tool": {"type": "string", "description": "Prefixed tool name, e.g. 'github__list_prs'."},
                "verdict": {
                    "type": "string",
                    "enum": [
                        "allow",
                        "warn",
                        "block",
                        "approval_pending",
                        "approved",
                        "denied",
                        "expired",
                        "error",
                    ],
                },
                "order": {"type": "string", "enum": ["newest", "tokens", "latency"], "default": "newest"},
                "limit": _LIMIT,
                "cursor": {"type": "string", "description": "next_cursor from a previous call."},
                "response_format": _FORMAT,
            },
            "additionalProperties": False,
        },
        output_schema={
            "type": "object",
            "properties": {"requests": {"type": "array", "items": {"type": "object"}}, "page": _PAGE},
            "required": ["requests", "page"],
        },
        annotations=READ_ONLY,
    ),
    types.Tool(
        name="shield_get_token_usage",
        title="Estimated token usage",
        description=(
            "Estimated context tokens contributed by MCP traffic, grouped by tool, server, connection or method, "
            "largest first. Counts are estimates of MCP payloads entering model context, not billed model tokens."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "since": _SINCE,
                "group_by": {
                    "type": "string",
                    "enum": ["tool", "server", "connection", "method"],
                    "default": "tool",
                },
                "limit": {**_LIMIT, "default": 10},
                "response_format": _FORMAT,
            },
            "additionalProperties": False,
        },
        output_schema={
            "type": "object",
            "properties": {
                "group_by": {"type": "string"},
                "rows": {"type": "array", "items": {"type": "object"}},
                "estimated": {"type": "boolean"},
            },
            "required": ["group_by", "rows", "estimated"],
        },
        annotations=READ_ONLY,
    ),
    types.Tool(
        name="shield_list_security_events",
        title="Security events",
        description=(
            "Security findings grouped by rule (blocked injections, redactions, approvals, rug-pulls), most "
            "severe first, with counts and the latest request id for each."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "since": _SINCE,
                "min_severity": {"type": "string", "enum": list(SEVERITY_RANK), "default": "medium"},
                "limit": _LIMIT,
                "response_format": _FORMAT,
            },
            "additionalProperties": False,
        },
        output_schema={
            "type": "object",
            "properties": {"events": {"type": "array", "items": {"type": "object"}}},
            "required": ["events"],
        },
        annotations=READ_ONLY,
    ),
]
NAMES = {t.name for t in TOOLS}


class AuditTools:
    def __init__(self, store: AuditStore, flush: Callable[[], Awaitable[bool]] | None = None):
        self.store = store
        self.flush = flush  # the audit logger's flush: an agent sees its own latest calls
        self.tools = {t.name: t for t in TOOLS}

    async def call(self, name: str, args: dict[str, Any]) -> types.CallToolResult:
        if self.flush is not None:
            await self.flush()
        try:
            return await anyio.to_thread.run_sync(self._call, name, args)
        except ValueError as e:
            return _error(str(e))

    def _call(self, name: str, a: dict[str, Any]) -> types.CallToolResult:
        since = since_iso(a.get("since", "24h"))
        fmt = a.get("response_format", "markdown")
        if name == "shield_list_requests":
            offset = _decode_cursor(a.get("cursor"))
            limit = int(a.get("limit", 20))
            rows, total = list_requests(
                self.store,
                Filters(
                    since=since,
                    server_id=a.get("server"),
                    tool=a.get("tool"),
                    verdicts=[a["verdict"]] if a.get("verdict") else [],
                    order=a.get("order", "newest"),
                    limit=limit,
                    offset=offset,
                ),
            )
            slim = [
                {
                    k: r[k]
                    for k in (
                        "id",
                        "created_at",
                        "method",
                        "tool",
                        "verdict",
                        "total_tokens",
                        "response_tokens",
                        "latency_ms",
                        "error_message",
                    )
                }
                for r in rows
            ]
            has_more = offset + len(rows) < total
            page = {
                "total": total,
                "count": len(rows),
                "has_more": has_more,
                "next_cursor": f"o:{offset + len(rows)}" if has_more else None,
            }
            data: dict[str, Any] = {"requests": slim, "page": page}
            md = _md_requests(slim, page)
        elif name == "shield_get_token_usage":
            group_by = a.get("group_by", "tool")
            rows = token_usage(self.store, since, group_by, int(a.get("limit", 10)))
            data = {"group_by": group_by, "rows": rows, "estimated": True}
            md = _md_tokens(group_by, rows)
        elif name == "shield_list_security_events":
            events = security_events(
                self.store, since, a.get("min_severity", "medium"), int(a.get("limit", 20))
            )
            data = {"events": events}
            md = _md_events(events)
        else:
            raise ValueError(f"unknown tool {name}")
        text = json.dumps(data, indent=2) if fmt == "json" else md
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=text)], structured_content=data
        )


def _decode_cursor(cursor: str | None) -> int:
    if not cursor:
        return 0
    if not cursor.startswith("o:") or not cursor[2:].isdigit():
        raise ValueError("invalid cursor; pass the next_cursor value from the previous response unchanged")
    return int(cursor[2:])


def _error(msg: str) -> types.CallToolResult:
    hint = " Valid 'since' values: " + ", ".join(RANGES) + "." if "range" in msg else ""
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=f"Error: {msg}.{hint}")], is_error=True
    )


def _md_requests(rows: list[dict[str, Any]], page: dict[str, Any]) -> str:
    if not rows:
        return "No requests match. Try a wider `since` (for example `7d` or `all`) or remove filters."
    lines = [
        f"**{page['total']:,} requests** (showing {page['count']}; tokens are estimates)",
        "",
        "| time (UTC) | tool | verdict | tokens | ms |",
        "|---|---|---|---:|---:|",
    ]
    for r in rows:
        lines.append(
            f"| {r['created_at'][5:19].replace('T', ' ')} | {r['tool'] or r['method']} | {r['verdict']} | "
            f"{r['total_tokens']:,} | {r['latency_ms']:.1f} |"
        )
    if page["has_more"]:
        lines += ["", f'More results: call again with `cursor: "{page["next_cursor"]}"`.']
    return "\n".join(lines)


def _md_tokens(group_by: str, rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "No token data in this window. Try `since: all`."
    lines = [
        f"**Estimated tokens by {group_by}** (MCP payloads entering model context)",
        "",
        f"| {group_by} | calls | total | response | avg response |",
        "|---|---:|---:|---:|---:|",
    ]
    for r in rows:
        lines.append(
            f"| {r['key']} | {r['calls']:,} | {r['total_tokens']:,} | {r['response_tokens']:,} | "
            f"{r['avg_response_tokens']:,} |"
        )
    return "\n".join(lines)


def _md_events(events: list[dict[str, Any]]) -> str:
    if not events:
        return "No security events in this window."
    lines = ["**Security events**", "", "| severity | rule | count | last seen |", "|---|---|---:|---|"]
    for e in events:
        lines.append(
            f"| {e['severity']} | {e['rule_id']} | {e['count']:,} | {e['last_seen'][:19].replace('T', ' ')} |"
        )
    return "\n".join(lines)
