"""Evidence export (TS-C5): CSV or JSON of audit rows. Payloads are opt-in and always redacted."""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from mcp_shield.audit.queries import Filters, list_requests
from mcp_shield.audit.store import AuditStore

COLUMNS = [
    "id",
    "created_at",
    "connection_id",
    "logical_call_id",
    "leg",
    "protocol_version",
    "method",
    "server_id",
    "tool",
    "verdict",
    "error_message",
    "latency_ms",
    "upstream_ms",
    "approval_ms",
    "request_tokens",
    "response_tokens",
    "schema_tokens",
    "total_tokens",
    "est_cost_usd",
    "tokenizer",
    "rule_ids",
]


def export_rows(
    store: AuditStore, filters: Filters, *, payloads: bool = False, batch: int = 1000
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    f = Filters(**{**filters.__dict__, "limit": batch, "offset": 0})
    while True:
        rows, _ = list_requests(store, f)
        if not rows:
            break
        ids = [r["id"] for r in rows]
        marks = ",".join("?" * len(ids))
        rules: dict[str, list[str]] = {}
        for fr in store.query(
            f"SELECT request_id, rule_id FROM findings WHERE request_id IN ({marks})", tuple(ids)
        ):
            rules.setdefault(fr["request_id"], []).append(fr["rule_id"])
        extra: dict[str, dict[str, Any]] = {}
        if payloads:
            for pr in store.query(
                f"SELECT id, params_redacted, result_redacted FROM requests WHERE id IN ({marks})", tuple(ids)
            ):
                extra[pr["id"]] = pr
        for r in rows:
            row = {c: r.get(c) for c in COLUMNS if c != "rule_ids"}
            row["rule_ids"] = ";".join(sorted(rules.get(r["id"], [])))
            row["tokens_estimated"] = True
            if payloads:
                row["params_redacted"] = extra[r["id"]]["params_redacted"]
                row["result_redacted"] = extra[r["id"]]["result_redacted"]
            out.append(row)
        if len(rows) < batch:
            break
        f.offset += batch
    return out


def to_csv(rows: list[dict[str, Any]]) -> str:
    buf = io.StringIO()
    fields = list(rows[0]) if rows else [*COLUMNS, "tokens_estimated"]
    w = csv.DictWriter(buf, fieldnames=fields)
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue()


def to_json(rows: list[dict[str, Any]]) -> str:
    return json.dumps({"tokens_are_estimates": True, "count": len(rows), "requests": rows}, indent=2)
