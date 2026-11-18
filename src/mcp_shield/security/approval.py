"""Human approval for risky calls (TS-B6, MP-B5, UJ-C4).

2026-07-28 has no server-to-client requests, so approval is a *multi-round-trip*:

    leg 1: Shield returns InputRequiredResult (an approval question) + request_state
           {logical_call_id, args_hash, issued_at}. Audited as ``approval_pending``.
    leg 2: the client asks the user and repeats the same tools/call with the answer.
           Shield checks the answer, the args hash and the expiry, then forwards
           (``approved``) or refuses (``denied`` / ``expired``).

``request_state`` is sealed by the SDK's ``RequestStateBoundary`` (installed in
server_face), so the client can't forge or edit it. Legacy 2025-11-25 clients get
a live ``elicitation/create`` inside the single request instead.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any

import anyio
from mcp import types
from mcp.server import ServerRequestContext
from mcp.types import CLIENT_CAPABILITIES_META_KEY

from mcp_shield.audit.models import Finding
from mcp_shield.metering.meter import canonical_json
from mcp_shield.pipeline.context import RequestContext

APPROVAL_KEY = "mcp_shield_approval"
MODERN = "2026-07-28"
SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"approve": {"type": "boolean", "title": "Allow this call?"}},
    "required": ["approve"],
}


def args_hash(tool: str, arguments: dict[str, Any] | None) -> str:
    return hashlib.sha256(f"{tool}\n{canonical_json(arguments or {})}".encode()).hexdigest()[:32]


def is_modern(protocol_version: str | None) -> bool:
    return bool(protocol_version) and str(protocol_version) >= MODERN


def parse_state(raw: str | None) -> dict[str, Any] | None:
    if not raw:
        return None
    try:
        state = json.loads(raw)
    except (TypeError, ValueError):
        return None
    return state if isinstance(state, dict) and state.get("v") == 1 and "lc" in state else None


def client_can_elicit(sctx: ServerRequestContext[Any]) -> bool:
    caps = sctx.session.client_capabilities
    if caps is not None and caps.elicitation is not None:
        return True
    meta = sctx.meta
    raw = (meta if isinstance(meta, dict) else meta.model_dump(by_alias=True)) if meta is not None else {}
    declared = raw.get(CLIENT_CAPABILITIES_META_KEY) or {}
    return isinstance(declared, dict) and declared.get("elicitation") is not None


def question(rctx: RequestContext, reason: str, arguments: dict[str, Any] | None) -> str:
    shown = canonical_json(arguments or {})
    if len(shown) > 300:
        shown = shown[:297] + "…"
    return f"MCP Shield: allow {rctx.tool} with {shown}? Reason: {reason}."


class Approver:
    def __init__(self, ttl_s: float = 300.0, clock: Any = time.time):
        self.ttl_s = ttl_s
        self.clock = clock

    def prepare_retry(self, rctx: RequestContext, params: types.CallToolRequestParams) -> None:
        """On leg 2, adopt leg 1's logical call id so both rows link (and args aren't counted twice)."""
        state = parse_state(params.request_state)
        if state is not None:
            rctx.logical_call_id = str(state["lc"])
            rctx.leg = 2

    async def check(
        self,
        rctx: RequestContext,
        sctx: ServerRequestContext[Any],
        params: types.CallToolRequestParams,
        reason: str,
    ) -> types.InputRequiredResult | None:
        """Decide an approval. Returns an InputRequiredResult for leg 1, else sets the verdict and returns None."""
        if not client_can_elicit(sctx):
            rctx.add_finding(
                Finding(stage="approval", rule_id="approval.unsupported_client", severity="medium")
            )
            rctx.escalate("denied", f"approval required ({reason}), but this client cannot prompt the user")
            return None
        if is_modern(sctx.protocol_version):
            return self._multi_round_trip(rctx, params, reason)
        await self._live(rctx, sctx, params, reason)
        return None

    def _multi_round_trip(
        self, rctx: RequestContext, params: types.CallToolRequestParams, reason: str
    ) -> types.InputRequiredResult | None:
        answer = (params.input_responses or {}).get(APPROVAL_KEY)
        state = parse_state(params.request_state)
        if answer is None or state is None:
            rctx.escalate("approval_pending", f"approval required: {reason}")
            new_state = {
                "v": 1,
                "lc": rctx.logical_call_id,
                "h": args_hash(rctx.tool or "", params.arguments),
                "iat": self.clock(),
            }
            ask = types.ElicitRequest(
                params=types.ElicitRequestFormParams(
                    message=question(rctx, reason, params.arguments), requested_schema=SCHEMA
                )
            )
            return types.InputRequiredResult(
                input_requests={APPROVAL_KEY: ask}, request_state=json.dumps(new_state)
            )

        rctx.approval_ms = round((self.clock() - float(state["iat"])) * 1000, 3)
        if state.get("h") != args_hash(rctx.tool or "", params.arguments):
            rctx.add_finding(Finding(stage="approval", rule_id="approval.args_changed", severity="high"))
            rctx.escalate("denied", "the arguments changed after approval was requested")
        elif self.clock() - float(state["iat"]) > self.ttl_s:
            rctx.escalate(
                "expired",
                f"approval expired ({self.ttl_s:g}s); call the tool again to request a new approval",
            )
        else:
            self._apply_answer(rctx, answer)
        return None

    async def _live(
        self,
        rctx: RequestContext,
        sctx: ServerRequestContext[Any],
        params: types.CallToolRequestParams,
        reason: str,
    ) -> None:
        start = self.clock()
        answer: types.ElicitResult | None = None
        with anyio.move_on_after(self.ttl_s):
            answer = await sctx.session.elicit_form(
                question(rctx, reason, params.arguments), SCHEMA, related_request_id=sctx.request_id
            )
        rctx.approval_ms = round((self.clock() - start) * 1000, 3)
        if answer is None:
            rctx.escalate("expired", f"no approval received within {self.ttl_s:g}s")
        else:
            self._apply_answer(rctx, answer)

    @staticmethod
    def _apply_answer(rctx: RequestContext, answer: Any) -> None:
        ok = (
            isinstance(answer, types.ElicitResult)
            and answer.action == "accept"
            and bool((answer.content or {}).get("approve"))
        )
        if ok:
            rctx.escalate("approved")
        else:
            rctx.escalate("denied", "denied by the user")
