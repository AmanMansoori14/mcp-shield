"""The ordered request pipeline (TS-A7, IP pipeline steps 1-13).

Wave 1 wires the skeleton every later stage plugs into:

    receive → meter.request → [pre-stages] → validate+forward → [post-stages] → meter.response
            → decide → audit.enqueue → respond

Pre-stages (policy, arg scanner, approval) and post-stages (result scanner, redactor,
context budget) are lists of hooks filled in wave 2. Guarantees already enforced here:

* every request produces exactly one audit record, including errors (MP-C2);
* an internal failure fails *closed*: verdict ``error``, nothing forwarded (MP-C5);
* denials go back to the model as ``is_error`` tool results with a readable reason (MP-C10);
* per-stage latency is recorded.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Sequence
from typing import Any, Protocol

from mcp import types
from pydantic import BaseModel

from mcp_shield import __version__
from mcp_shield.audit.logger import AuditLogger
from mcp_shield.audit.models import AuditRecord, Finding, TokenRecord
from mcp_shield.metering.meter import Meter, TokenUsage, canonical_json
from mcp_shield.pipeline.context import RequestContext

log = logging.getLogger(__name__)

SHIELD_META = "io.mcpshield/decision"


class PreStage(Protocol):
    """Runs before forwarding. Calls ``ctx.escalate("block", reason)`` to stop the call."""

    name: str

    async def __call__(self, ctx: RequestContext) -> None: ...


class PostStage(Protocol):
    """Runs on the upstream result; may return a modified result (e.g. redacted)."""

    name: str

    async def __call__(self, ctx: RequestContext, result: types.CallToolResult) -> types.CallToolResult: ...


STOPPING = {"block", "denied", "expired", "approval_pending", "error"}

Approve = Callable[[RequestContext], Awaitable[types.InputRequiredResult | None]]


class Pipeline:
    def __init__(
        self,
        meter: Meter,
        audit: AuditLogger,
        *,
        policy_hash: str | Callable[[], str | None] | None,
        store_payloads: bool = False,
        max_payload_bytes: int = 65_536,
        pre_stages: Sequence[PreStage] = (),
        post_stages: Sequence[PostStage] = (),
        fail_open: bool = False,
        redact: Callable[[Any], Any] | None = None,
    ):
        self.meter = meter
        self.audit = audit
        self.policy_hash = policy_hash
        self.store_payloads = store_payloads
        self.max_payload_bytes = max_payload_bytes
        self.pre_stages = list(pre_stages)
        self.post_stages = list(post_stages)
        self.fail_open = fail_open
        self.redact = redact

    # -- tools/call ----------------------------------------------------------

    async def call_tool(
        self,
        ctx: RequestContext,
        forward: Callable[[], Awaitable[types.CallToolResult]],
        approve: Approve | None = None,
    ) -> types.CallToolResult | types.InputRequiredResult:
        usage = TokenUsage(tokenizer=self.meter.tokenizer.name)
        result: types.CallToolResult | types.InputRequiredResult | None = None
        try:
            with ctx.stage("meter.request"):
                # Leg 2 of an approval repeats leg 1's arguments: count them once per logical call.
                req_tokens = (
                    0
                    if ctx.leg == 2
                    else await self.meter.request_tokens((ctx.params or {}).get("arguments"))
                )

            for stage in self.pre_stages:
                with ctx.stage(stage.name):
                    await stage(ctx)
                if ctx.verdict in STOPPING:
                    break

            if ctx.verdict not in STOPPING and ctx.needs_approval:
                if approve is None:
                    ctx.escalate(
                        "denied", f"approval required ({ctx.approval_reason}) but approvals are unavailable"
                    )
                else:
                    with ctx.stage("approval"):
                        pending = await approve(ctx)
                    if pending is not None:
                        result = pending
                        usage = self.meter.usage(request=req_tokens)
                        return pending

            if ctx.verdict in STOPPING:
                result = self.denial(ctx)
            else:
                with ctx.stage("upstream"):
                    result = await forward()
                ctx.upstream_ms = ctx.stage_ms.get("upstream")
                for post in self.post_stages:
                    with ctx.stage(post.name):
                        result = await post(ctx, result)
                if ctx.verdict in STOPPING:
                    result = self.denial(ctx)

            assert isinstance(result, types.CallToolResult)
            with ctx.stage("meter.response"):
                resp_tokens = 0
                if ctx.verdict not in STOPPING:
                    resp_tokens = await self.meter.content_tokens(result.content, result.structured_content)
            usage = self.meter.usage(request=req_tokens, response=resp_tokens)
            return result
        except Exception as e:
            log.exception("pipeline failure on %s (request %s)", ctx.tool, ctx.request_id)
            ctx.add_finding(
                Finding(
                    stage="pipeline",
                    rule_id="internal.error",
                    severity="high",
                    excerpt_redacted=type(e).__name__,
                )
            )
            ctx.escalate("error", "internal Shield error; the call was blocked (fail-closed)")
            result = self.denial(ctx)
            return result
        finally:
            self._submit(ctx, usage, result)

    def denial(self, ctx: RequestContext) -> types.CallToolResult:
        """A tool result the *model* can read (MP-C10), with machine-readable details in ``_meta``."""
        label = {
            "block": "Blocked",
            "denied": "Denied",
            "expired": "Approval expired",
            "error": "Blocked (error)",
            "approval_pending": "Approval required",
        }.get(ctx.verdict, ctx.verdict)
        reason = f": {ctx.reason}" if ctx.reason else ""
        text = f"[MCP Shield] {label}{reason}. Request ID {ctx.request_id}."
        meta = {
            SHIELD_META: {
                "verdict": ctx.verdict,
                "request_id": ctx.request_id,
                "rule_ids": [f.rule_id for f in ctx.findings],
            }
        }
        result = types.CallToolResult(content=[types.TextContent(type="text", text=text)], is_error=True)
        result.meta = meta
        return result

    # -- everything else (lists, reads, prompts) --------------------------------

    async def observe(
        self,
        ctx: RequestContext,
        run: Callable[[], Awaitable[Any]],
        measure: Callable[[Any], Awaitable[TokenUsage]],
    ) -> Any:
        """Audit + meter a non-tool request. Errors are recorded and re-raised to the SDK."""
        usage = TokenUsage(tokenizer=self.meter.tokenizer.name)
        result: Any = None
        try:
            with ctx.stage("upstream"):
                result = await run()
            ctx.upstream_ms = ctx.stage_ms.get("upstream")
            with ctx.stage("meter.response"):
                usage = await measure(result)
            return result
        except Exception as e:
            ctx.escalate("error", str(e) or type(e).__name__)
            ctx.error_code = getattr(getattr(e, "error", None), "code", None)
            raise
        finally:
            self._submit(ctx, usage, result)

    # -- audit ---------------------------------------------------------------------

    def _submit(self, ctx: RequestContext, usage: TokenUsage, result: Any) -> None:
        try:
            params_s, p_trunc = self._payload(ctx.params)
            result_s, r_trunc = self._payload(result)
            rec = AuditRecord(
                id=ctx.request_id,
                connection=ctx.connection,
                logical_call_id=ctx.logical_call_id,
                leg=ctx.leg,
                protocol_version=ctx.protocol_version,
                jsonrpc_id=ctx.jsonrpc_id,
                method=ctx.method,
                server_id=ctx.server_id,
                tool=ctx.tool,
                verdict=ctx.verdict,  # type: ignore[arg-type]
                error_code=ctx.error_code,
                error_message=ctx.reason if ctx.verdict in STOPPING else None,
                latency_ms=ctx.elapsed_ms,
                upstream_ms=ctx.upstream_ms,
                approval_ms=ctx.approval_ms,
                stage_ms=dict(ctx.stage_ms),
                params_redacted=params_s,
                result_redacted=result_s,
                payload_truncated=p_trunc or r_trunc,
                policy_hash=self.policy_hash() if callable(self.policy_hash) else self.policy_hash,
                shield_version=__version__,
                tokens=TokenRecord(
                    request_tokens=usage.request_tokens,
                    response_tokens=usage.response_tokens,
                    schema_tokens=usage.schema_tokens,
                    total_tokens=usage.total_tokens,
                    est_cost_usd=usage.est_cost_usd,
                    tokenizer=usage.tokenizer,
                    estimated=usage.estimated,
                ),
                findings=list(ctx.findings),
            )
            self.audit.submit(rec)
        except Exception:  # auditing must never take the request down with it
            log.exception("failed to build audit record for %s", ctx.request_id)

    def _payload(self, value: Any) -> tuple[str | None, bool]:
        # Payloads are stored only through the redactor - raw secrets never go to disk (MP-C3).
        if not self.store_payloads or self.redact is None or value is None:
            return None, False
        if isinstance(value, BaseModel):
            value = value.model_dump(mode="json", by_alias=True, exclude_none=True)
        text = canonical_json(self.redact(value))
        if len(text.encode()) <= self.max_payload_bytes:
            return text, False
        return text.encode()[: self.max_payload_bytes].decode(errors="ignore"), True
