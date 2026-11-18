"""Audit records: one per JSON-RPC request (MP-B6, MP-C2)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field

Verdict = Literal["allow", "warn", "block", "approval_pending", "approved", "denied", "expired", "error"]
Severity = Literal["info", "low", "medium", "high", "critical"]
ConnectionKind = Literal["stdio", "legacy_session", "grouped", "in_process"]

# Worst-of ordering used to combine stage verdicts (IP pipeline step 11).
VERDICT_RANK: dict[str, int] = {
    "allow": 0,
    "approved": 1,
    "warn": 2,
    "approval_pending": 3,
    "expired": 4,
    "denied": 5,
    "block": 6,
    "error": 7,
}


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def worst(a: str, b: str) -> str:
    return a if VERDICT_RANK[a] >= VERDICT_RANK[b] else b


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: new_id("f"))
    stage: str
    rule_id: str
    severity: Severity = "info"
    target: str | None = None
    snippet_hash: str | None = None
    excerpt_redacted: str | None = None


class TokenRecord(BaseModel):
    request_tokens: int = 0
    response_tokens: int = 0
    schema_tokens: int = 0
    total_tokens: int = 0
    est_cost_usd: float | None = None
    tokenizer: str
    estimated: bool = True


class ConnectionRecord(BaseModel):
    id: str
    kind: ConnectionKind
    client_name: str | None = None
    client_version: str | None = None
    protocol_version: str | None = None
    capabilities: dict[str, object] | None = None
    started_at: str = Field(default_factory=now_iso)
    last_seen_at: str = Field(default_factory=now_iso)


class AuditRecord(BaseModel):
    id: str = Field(default_factory=lambda: new_id("r"))
    connection: ConnectionRecord
    logical_call_id: str = Field(default_factory=lambda: new_id("lc"))
    leg: int = 1
    protocol_version: str | None = None
    jsonrpc_id: str | None = None
    direction: Literal["client_to_server", "server_to_client", "upstream_to_shield"] = "client_to_server"
    method: str
    server_id: str | None = None
    tool: str | None = None
    verdict: Verdict
    error_code: int | None = None
    error_message: str | None = None
    latency_ms: float
    upstream_ms: float | None = None
    approval_ms: float | None = None
    stage_ms: dict[str, float] = Field(default_factory=dict)
    params_redacted: str | None = None
    result_redacted: str | None = None
    payload_truncated: bool = False
    policy_hash: str | None = None
    shield_version: str
    created_at: str = Field(default_factory=now_iso)
    tokens: TokenRecord
    findings: list[Finding] = Field(default_factory=list)


class UpstreamSnapshot(BaseModel):
    server_id: str
    status: Literal["up", "down", "degraded"]
    transport: str
    protocol_version: str | None = None
    tool_count: int = 0
    dropped_tools: list[dict[str, str]] = Field(default_factory=list)
    schema_tokens: int = 0
    last_error: str | None = None
    checked_at: str = Field(default_factory=now_iso)
