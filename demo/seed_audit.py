"""Seed an audit DB with deterministic, realistic traffic for the dashboard and evaluations.

    uv run python -m demo.seed_audit demo-audit.db --calls 2000

Same seed → same data, so evaluation answers stay stable. Timestamps are pinned to
2026-11-10 .. 2026-11-16 (UTC).
"""

from __future__ import annotations

import argparse
import hashlib
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

from mcp_shield.audit.models import AuditRecord, ConnectionRecord, Finding, TokenRecord
from mcp_shield.audit.store import AuditStore
from mcp_shield.config import PolicyFile, policy_hash

START = datetime(2026, 11, 10, tzinfo=UTC)
TOOLS: dict[str, list[tuple[str, int, int]]] = {  # server: [(tool, typical response tokens, weight)]
    "notes": [("echo", 12, 30), ("add", 6, 20), ("read_note", 900, 15)],
    "github": [("list_prs", 1400, 25), ("create_issue", 60, 10), ("merge_pull_request", 40, 6)],
    "fs": [("read_file", 2200, 30), ("write_file", 20, 8)],
    "evil": [("fetch_page", 400, 6)],
}
PRICE = 3.0  # USD per million input tokens


def seed(path: Path | str, calls: int = 2000, seed_value: int = 42) -> dict[str, int]:
    rng = random.Random(seed_value)
    store = AuditStore(path)
    ph = policy_hash(PolicyFile())
    store.register_policy(ph, "policy.yaml", "version: 1\n")
    conns = [
        ConnectionRecord(
            id=f"c_seed{i}",
            kind=kind,
            client_name=name,
            client_version="1.0",
            protocol_version=pv,
            started_at=START.isoformat(),
            last_seen_at=START.isoformat(),
        )
        for i, (kind, name, pv) in enumerate(
            [
                ("stdio", "claude-desktop", "2025-11-25"),
                ("stdio", "claude-code", "2026-07-28"),
                ("grouped", "cursor", "2026-07-28"),
            ]
        )
    ]
    flat = [(s, t, tok, w) for s, ts in TOOLS.items() for t, tok, w in ts]
    weights = [w for *_, w in flat]
    counts = {"calls": 0, "rows": 0}
    seq = 0

    def ts() -> str:
        nonlocal seq
        seq += 1
        return (START + timedelta(seconds=seq * (7 * 86400 / (calls * 1.3)))).isoformat(
            timespec="milliseconds"
        )

    def write(rec: AuditRecord) -> None:
        store.write(rec)
        counts["rows"] += 1

    for i in range(calls):
        conn = rng.choice(conns)
        server, tool, typical, _ = rng.choices(flat, weights=weights)[0]
        name = f"{server}__{tool}"
        req = rng.randint(8, 60)
        resp = max(1, int(rng.gauss(typical, typical * 0.35)))
        verdict, findings, reason = "allow", [], None
        upstream = round(rng.uniform(3, 120), 2)
        latency = round(upstream + rng.uniform(0.3, 6), 2)

        if i % 50 == 0:  # periodic tool listing
            write(
                AuditRecord(
                    connection=conn,
                    method="tools/list",
                    verdict="allow",
                    latency_ms=1.5,
                    shield_version="0.1.0",
                    policy_hash=ph,
                    created_at=ts(),
                    tokens=TokenRecord(
                        schema_tokens=1840,
                        total_tokens=1840,
                        tokenizer="tiktoken:o200k_base",
                        est_cost_usd=round(1840 * PRICE / 1e6, 8),
                    ),
                )
            )

        if name == "fs__read_file" and rng.random() < 0.06:
            verdict, reason = "block", "suspicious arguments (args.path_traversal)"
            findings = [Finding(stage="args", rule_id="args.path_traversal", severity="high")]
            resp, upstream, latency = 0, None, round(rng.uniform(0.3, 1.2), 2)
        elif name == "evil__fetch_page":
            verdict = "warn"
            findings = [
                Finding(stage="result", rule_id="injection.ignore_previous", severity="high"),
                Finding(stage="redaction", rule_id="redaction.aws_access_key", severity="medium"),
            ]
        elif name in ("fs__read_file", "notes__read_note") and resp > 4000:
            verdict = "warn"
            findings = [
                Finding(
                    stage="budget",
                    rule_id="budget.exceeded",
                    severity="low",
                    excerpt_redacted=f"{resp} tokens > budget 4000",
                )
            ]
        elif name == "github__merge_pull_request":
            lc = f"lc_seed{i}"
            write(
                AuditRecord(
                    connection=conn,
                    method="tools/call",
                    server_id=server,
                    tool=name,
                    verdict="approval_pending",
                    logical_call_id=lc,
                    leg=1,
                    latency_ms=0.9,
                    shield_version="0.1.0",
                    policy_hash=ph,
                    protocol_version=conn.protocol_version,
                    created_at=ts(),
                    findings=[Finding(stage="policy", rule_id="approve-destructive", severity="medium")],
                    tokens=TokenRecord(request_tokens=req, total_tokens=req, tokenizer="tiktoken:o200k_base"),
                )
            )
            approved = rng.random() < 0.7
            verdict = "approved" if approved else "denied"
            reason = None if approved else "denied by the user"
            req = 0  # leg 2 doesn't re-count arguments
            if not approved:
                resp, upstream = 0, None
            write(
                AuditRecord(
                    connection=conn,
                    method="tools/call",
                    server_id=server,
                    tool=name,
                    verdict=verdict,
                    logical_call_id=lc,
                    leg=2,
                    latency_ms=latency,
                    upstream_ms=upstream,
                    approval_ms=round(rng.uniform(2000, 40000), 1),
                    error_message=reason,
                    shield_version="0.1.0",
                    policy_hash=ph,
                    protocol_version=conn.protocol_version,
                    created_at=ts(),
                    tokens=TokenRecord(
                        request_tokens=0,
                        response_tokens=resp,
                        total_tokens=resp,
                        tokenizer="tiktoken:o200k_base",
                        est_cost_usd=round(resp * PRICE / 1e6, 8),
                    ),
                )
            )
            counts["calls"] += 1
            continue

        write(
            AuditRecord(
                connection=conn,
                method="tools/call",
                server_id=server,
                tool=name,
                verdict=verdict,
                error_message=reason,
                latency_ms=latency,
                upstream_ms=upstream,
                shield_version="0.1.0",
                policy_hash=ph,
                protocol_version=conn.protocol_version,
                created_at=ts(),
                findings=findings,
                tokens=TokenRecord(
                    request_tokens=req,
                    response_tokens=resp,
                    total_tokens=req + resp,
                    tokenizer="tiktoken:o200k_base",
                    est_cost_usd=round((req + resp) * PRICE / 1e6, 8),
                ),
            )
        )
        counts["calls"] += 1

    from mcp_shield.audit.models import UpstreamSnapshot

    for server, tools in TOOLS.items():
        store.write_upstream(
            UpstreamSnapshot(
                server_id=server,
                status="up",
                transport="stdio",
                protocol_version="2026-07-28",
                tool_count=len(tools),
                schema_tokens=sum(120 + 15 * len(t) for t, *_ in tools),
            )
        )
        for tool, *_ in tools:
            store.upsert_pin(server, tool, hashlib.sha256(f"{server}/{tool}".encode()).hexdigest(), "pinned")
    store.upsert_pin("evil", "get_weather", "0" * 12, "hidden")
    store.close()
    return counts


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("db", type=Path)
    ap.add_argument("--calls", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    if a.db.exists():
        raise SystemExit(f"{a.db} exists; remove it first")
    print(seed(a.db, a.calls, a.seed))


if __name__ == "__main__":
    main()
