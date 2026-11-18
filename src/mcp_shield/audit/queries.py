"""Read-side queries over the audit store (TS-C1..C5, TS-C8).

One query layer feeds the dashboard, ``shield stats``, ``shield export`` and the
``shield_*`` MCP tools, so every view agrees on the numbers. All queries are
parameterised; filters never interpolate user input into SQL.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from mcp_shield.audit.store import AuditStore

RANGES: dict[str, timedelta | None] = {
    "15m": timedelta(minutes=15),
    "1h": timedelta(hours=1),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
    "all": None,
}
BLOCKING = ("block", "denied", "error", "expired")
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def since_iso(range_key: str, now: datetime | None = None) -> str | None:
    if range_key not in RANGES:
        raise ValueError(f"unknown range {range_key!r}; use one of {', '.join(RANGES)}")
    delta = RANGES[range_key]
    if delta is None:
        return None
    return ((now or datetime.now(UTC)) - delta).isoformat(timespec="milliseconds")


@dataclass
class Filters:
    since: str | None = None
    until: str | None = None
    connection_id: str | None = None
    protocol_version: str | None = None
    server_id: str | None = None
    tool: str | None = None
    method: str | None = None
    verdicts: list[str] = field(default_factory=list)
    min_tokens: int | None = None
    text: str | None = None
    limit: int = 50
    offset: int = 0
    order: str = "newest"  # newest | tokens | latency

    def where(self) -> tuple[str, list[Any]]:
        clauses: list[str] = []
        args: list[Any] = []
        for col, val in (
            ("r.created_at >= ?", self.since),
            ("r.created_at <= ?", self.until),
            ("r.connection_id = ?", self.connection_id),
            ("r.protocol_version = ?", self.protocol_version),
            ("r.server_id = ?", self.server_id),
            ("r.tool = ?", self.tool),
            ("r.method = ?", self.method),
            ("t.total_tokens >= ?", self.min_tokens),
        ):
            if val is not None and val != "":
                clauses.append(col)
                args.append(val)
        if self.verdicts:
            clauses.append(f"r.verdict IN ({','.join('?' * len(self.verdicts))})")
            args.extend(self.verdicts)
        if self.text:
            clauses.append(
                "(r.tool LIKE ? OR r.id = ? OR r.logical_call_id = ? OR EXISTS "
                "(SELECT 1 FROM findings f WHERE f.request_id = r.id AND f.rule_id LIKE ?))"
            )
            like = f"%{self.text}%"
            args.extend([like, self.text, self.text, like])
        return (" WHERE " + " AND ".join(clauses)) if clauses else "", args


_ORDER = {
    "newest": "r.created_at DESC",
    "tokens": "t.total_tokens DESC, r.created_at DESC",
    "latency": "r.latency_ms DESC, r.created_at DESC",
}

_REQUEST_COLS = """r.id, r.created_at, r.connection_id, r.logical_call_id, r.leg, r.protocol_version, r.method,
    r.server_id, r.tool, r.verdict, r.error_message, r.latency_ms, r.upstream_ms, r.approval_ms,
    t.request_tokens, t.response_tokens, t.schema_tokens, t.total_tokens, t.est_cost_usd, t.tokenizer"""


def list_requests(store: AuditStore, f: Filters) -> tuple[list[dict[str, Any]], int]:
    where, args = f.where()
    base = f"FROM requests r JOIN token_usage t ON t.request_id = r.id{where}"
    total = int(store.scalar(f"SELECT COUNT(*) {base}", tuple(args)) or 0)
    rows = store.query(
        f"SELECT {_REQUEST_COLS} {base} ORDER BY {_ORDER.get(f.order, _ORDER['newest'])} LIMIT ? OFFSET ?",
        (*args, max(1, min(f.limit, 1000)), max(0, f.offset)),
    )
    return rows, total


def get_request(store: AuditStore, request_id: str) -> dict[str, Any] | None:
    rows = store.query(
        f"""SELECT {_REQUEST_COLS}, r.jsonrpc_id, r.error_code, r.stage_ms, r.params_redacted, r.result_redacted,
            r.payload_truncated, r.policy_hash, r.shield_version, t.estimated
            FROM requests r JOIN token_usage t ON t.request_id = r.id WHERE r.id = ?""",
        (request_id,),
    )
    if not rows:
        return None
    req = rows[0]
    req["stage_ms"] = json.loads(req["stage_ms"] or "{}")
    req["findings"] = store.query(
        "SELECT stage, rule_id, severity, target, excerpt_redacted FROM findings WHERE request_id = ? "
        "ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
        "WHEN 'low' THEN 3 ELSE 4 END, rule_id",
        (request_id,),
    )
    req["legs"] = store.query(
        "SELECT id, leg, verdict, created_at FROM requests WHERE logical_call_id = ? ORDER BY leg, created_at",
        (req["logical_call_id"],),
    )
    conn = store.query("SELECT * FROM connections WHERE id = ?", (req["connection_id"],))
    req["connection"] = conn[0] if conn else None
    policy = store.query(
        "SELECT hash, loaded_at, yaml_source FROM policy_versions WHERE hash = ?", (req["policy_hash"],)
    )
    req["policy"] = policy[0] if policy else None
    return req


def overview(store: AuditStore, since: str | None) -> dict[str, Any]:
    cond, args = ("WHERE r.created_at >= ?", (since,)) if since else ("", ())
    row = store.query(
        f"""SELECT COUNT(*) AS requests,
            COALESCE(SUM(r.verdict IN ('block','denied','error','expired')), 0) AS blocked,
            COALESCE(SUM(r.verdict = 'warn'), 0) AS warned,
            COALESCE(SUM(t.total_tokens), 0) AS total_tokens,
            COALESCE(SUM(t.response_tokens), 0) AS response_tokens,
            SUM(t.est_cost_usd) AS est_cost_usd
            FROM requests r JOIN token_usage t ON t.request_id = r.id {cond}""",
        args,
    )[0]
    overheads = [
        r["o"]
        for r in store.query(
            f"""SELECT r.latency_ms - COALESCE(r.upstream_ms, 0) - COALESCE(r.approval_ms, 0) AS o
                FROM requests r {cond}{" AND" if cond else " WHERE"} r.method = 'tools/call' ORDER BY o""",
            args,
        )
    ]
    row["p95_overhead_ms"] = round(overheads[int(len(overheads) * 0.95)] if overheads else 0.0, 2)
    row["blocked_pct"] = round(100 * row["blocked"] / row["requests"], 1) if row["requests"] else 0.0
    return row


def timeseries(store: AuditStore, since: str | None, bucket: str = "hour") -> list[dict[str, Any]]:
    width = {"minute": 16, "hour": 13, "day": 10}[bucket]
    cond, args = ("WHERE r.created_at >= ?", (since,)) if since else ("", ())
    return store.query(
        f"""SELECT substr(r.created_at, 1, {width}) AS bucket, r.verdict, COALESCE(r.server_id, 'shield') AS server_id,
            COUNT(*) AS requests, SUM(t.total_tokens) AS tokens
            FROM requests r JOIN token_usage t ON t.request_id = r.id {cond}
            GROUP BY bucket, r.verdict, server_id ORDER BY bucket""",
        args,
    )


def token_usage(
    store: AuditStore, since: str | None, group_by: str = "tool", limit: int = 10
) -> list[dict[str, Any]]:
    column = {
        "tool": "r.tool",
        "server": "r.server_id",
        "connection": "r.connection_id",
        "method": "r.method",
    }
    if group_by not in column:
        raise ValueError(f"group_by must be one of {', '.join(column)}")
    conds = ["r.method = 'tools/call'"] if group_by in ("tool", "server") else []
    args: list[Any] = []
    if since:
        conds.append("r.created_at >= ?")
        args.append(since)
    where = (" WHERE " + " AND ".join(conds)) if conds else ""
    return store.query(
        f"""SELECT {column[group_by]} AS key, COUNT(*) AS calls,
            SUM(t.request_tokens) AS request_tokens, SUM(t.response_tokens) AS response_tokens,
            SUM(t.schema_tokens) AS schema_tokens, SUM(t.total_tokens) AS total_tokens,
            ROUND(AVG(t.response_tokens), 1) AS avg_response_tokens, MAX(t.response_tokens) AS max_response_tokens,
            SUM(t.est_cost_usd) AS est_cost_usd
            FROM requests r JOIN token_usage t ON t.request_id = r.id{where}
            GROUP BY key ORDER BY total_tokens DESC, key LIMIT ?""",
        (*args, max(1, min(limit, 200))),
    )


def security_events(
    store: AuditStore, since: str | None, min_severity: str = "medium", limit: int = 50
) -> list[dict[str, Any]]:
    allowed = [s for s, r in SEVERITY_RANK.items() if r >= SEVERITY_RANK[min_severity]]
    args: list[Any] = list(allowed)
    cond = f"f.severity IN ({','.join('?' * len(allowed))})"
    if since:
        cond += " AND r.created_at >= ?"
        args.append(since)
    return store.query(
        f"""SELECT f.rule_id, f.severity, f.stage, COUNT(*) AS count, COUNT(DISTINCT r.tool) AS tools,
            MIN(r.created_at) AS first_seen, MAX(r.created_at) AS last_seen,
            (SELECT r2.id FROM findings f2 JOIN requests r2 ON r2.id = f2.request_id
             WHERE f2.rule_id = f.rule_id ORDER BY r2.created_at DESC LIMIT 1) AS latest_request_id
            FROM findings f JOIN requests r ON r.id = f.request_id WHERE {cond}
            GROUP BY f.rule_id, f.severity, f.stage
            ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
                     count DESC LIMIT ?""",
        (*args, max(1, min(limit, 500))),
    )


def upstreams(store: AuditStore) -> list[dict[str, Any]]:
    rows = store.query("SELECT * FROM upstreams ORDER BY server_id")
    for r in rows:
        r["dropped_tools"] = json.loads(r["dropped_tools"] or "[]")
    return rows


def tool_pins(store: AuditStore) -> list[dict[str, Any]]:
    return store.query("SELECT * FROM tool_pins ORDER BY server_id, tool")


def current_policy(store: AuditStore) -> dict[str, Any] | None:
    rows = store.query("SELECT * FROM policy_versions ORDER BY loaded_at DESC LIMIT 1")
    return rows[0] if rows else None


def budget_breaches(store: AuditStore, since: str | None, limit: int = 20) -> list[dict[str, Any]]:
    cond, args = ("AND r.created_at >= ?", [since]) if since else ("", [])
    return store.query(
        f"""SELECT r.id, r.created_at, r.tool, t.response_tokens, f.excerpt_redacted
            FROM findings f JOIN requests r ON r.id = f.request_id JOIN token_usage t ON t.request_id = r.id
            WHERE f.rule_id = 'budget.exceeded' {cond} ORDER BY t.response_tokens DESC LIMIT ?""",
        (*args, limit),
    )
