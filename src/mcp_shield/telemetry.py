"""OpenTelemetry enrichment (TS-C9, MP-B9).

The MCP SDK v2 already opens a server span for every message (with GenAI semantic
conventions on ``tools/call``). Shield adds its decision to that same span, so a
tracing backend shows *why* a call was blocked and what it cost. No exporter is
configured here: the attributes cost nothing until the process installs one.
"""

from __future__ import annotations

from opentelemetry import trace

from mcp_shield.metering.meter import TokenUsage
from mcp_shield.pipeline.context import RequestContext


def annotate_span(ctx: RequestContext, usage: TokenUsage) -> None:
    span = trace.get_current_span()
    if not span.is_recording():
        return
    span.set_attributes(
        {
            "shield.verdict": ctx.verdict,
            "shield.request_id": ctx.request_id,
            "shield.logical_call_id": ctx.logical_call_id,
            "shield.leg": ctx.leg,
            "shield.server_id": ctx.server_id or "",
            "shield.rule_ids": sorted({f.rule_id for f in ctx.findings}),
            "shield.tokens.request": usage.request_tokens,
            "shield.tokens.response": usage.response_tokens,
            "shield.tokens.schema": usage.schema_tokens,
            "shield.tokens.total": usage.total_tokens,
            "shield.tokens.estimated": usage.estimated,
            "shield.tokenizer": usage.tokenizer,
        }
    )
    if ctx.verdict in ("block", "denied", "expired", "error"):
        span.add_event("shield.denied", {"shield.reason": ctx.reason or ""})
