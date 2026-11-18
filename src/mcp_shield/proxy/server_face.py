"""Shield as an MCP *server* to clients (IP-A1, TS-A3, TS-A4).

Built on the SDK v2 low-level ``Server``: one process serves 2026-07-28 clients and
legacy 2025-11-25 clients. Every handler runs through the ``Pipeline`` so each
request is metered and audited.

Pass-through matrix (IP-A11):

* forwarded:        progress (server→client) for proxied tool calls; list-changed
                    notifications become a refresh plus a downstream ``list_changed``
* answered locally: ``ping`` (the SDK's built-in handler; never forwarded upstream)
* refused:          elicitation/sampling/roots requests from upstreams (see UpstreamPool)
"""

from __future__ import annotations

import logging
import weakref
from typing import Any

from mcp import MCPError, types
from mcp.server import Server, ServerRequestContext
from mcp.server.context import CallNext, HandlerResult
from mcp.server.request_state import RequestStateBoundary, RequestStateSecurity
from mcp.types import CLIENT_INFO_META_KEY, INVALID_PARAMS

from mcp_shield import __version__
from mcp_shield.audit.models import ConnectionKind, ConnectionRecord, Finding, new_id, now_iso
from mcp_shield.metering.meter import TokenUsage
from mcp_shield.pipeline.context import RequestContext
from mcp_shield.pipeline.pipeline import Pipeline
from mcp_shield.proxy import router
from mcp_shield.proxy.upstream_pool import UpstreamPool
from mcp_shield.security.approval import Approver
from mcp_shield.security.pins import ToolGuard

log = logging.getLogger(__name__)

INSTRUCTIONS = (
    "Tools are provided by several upstream MCP servers through MCP Shield, a security gateway. "
    "Tool names are prefixed with the server id (for example fs__read_file). Results starting "
    "with [MCP Shield] are decisions made by the gateway; explain them to the user."
)


class ConnectionTracker:
    """Maps live server sessions to audit ``connection`` rows (MP-C Connection).

    stdio and legacy HTTP sessions are one connection per session object. Grouping of
    2026-07-28 HTTP traffic by client info + token arrives with the HTTP face (TS-C6).
    """

    def __init__(self, kind: ConnectionKind):
        self.kind = kind
        self._by_session: weakref.WeakKeyDictionary[Any, ConnectionRecord] = weakref.WeakKeyDictionary()

    def for_request(self, ctx: ServerRequestContext[Any]) -> ConnectionRecord:
        rec = self._by_session.get(ctx.session)
        name, version = _client_info(ctx)
        if rec is None:
            caps = ctx.session.client_capabilities
            rec = ConnectionRecord(
                id=new_id("c"),
                kind=self.kind,
                client_name=name,
                client_version=version,
                protocol_version=ctx.protocol_version,
                capabilities=caps.model_dump(mode="json", exclude_none=True) if caps else None,
            )
            self._by_session[ctx.session] = rec
        else:
            rec = rec.model_copy(
                update={
                    "last_seen_at": now_iso(),
                    "client_name": rec.client_name or name,
                    "client_version": rec.client_version or version,
                }
            )
            self._by_session[ctx.session] = rec
        return rec

    def sessions(self) -> list[Any]:
        return list(self._by_session.keys())


def build_server(
    pool: UpstreamPool,
    pipeline: Pipeline,
    tracker: ConnectionTracker,
    *,
    guard: ToolGuard | None = None,
    approver: Approver | None = None,
) -> Server[Any]:
    meter = pipeline.meter

    def new_ctx(ctx: ServerRequestContext[Any], method: str, params: Any = None) -> RequestContext:
        dumped = (
            params.model_dump(mode="json", by_alias=True, exclude_none=True) if params is not None else None
        )
        return RequestContext(
            connection=tracker.for_request(ctx),
            method=method,
            protocol_version=ctx.protocol_version,
            jsonrpc_id=str(ctx.request_id) if ctx.request_id is not None else None,
            params=dumped,
        )

    # -- tools --------------------------------------------------------------------

    async def on_list_tools(
        ctx: ServerRequestContext[Any], params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        rctx = new_ctx(ctx, "tools/list", params)

        async def run() -> types.ListToolsResult:
            tools = [
                router.namespaced_tool(sid, t)
                for sid, t in pool.all_tools()
                if guard is None or not guard.is_hidden(sid, t.name)  # poisoned tools are hidden (MP-B3)
            ]
            if guard is not None:
                for f in guard.listing_findings():
                    rctx.add_finding(f)
                if rctx.findings:
                    rctx.escalate("warn")
            return types.ListToolsResult(tools=tools)

        async def measure(result: types.ListToolsResult) -> TokenUsage:
            return meter.usage(schema=await meter.definitions_tokens(result.tools))

        result: types.ListToolsResult = await pipeline.observe(rctx, run, measure)
        return result

    async def on_call_tool(
        ctx: ServerRequestContext[Any], params: types.CallToolRequestParams
    ) -> types.CallToolResult | types.InputRequiredResult:
        parts = router.split(params.name)
        up = pool.get(parts[0]) if parts else None
        if parts is None or up is None or (up.client is not None and parts[1] not in up.tools):
            # Not a gateway decision - the tool doesn't exist. Spec answer: -32602.
            rctx = new_ctx(ctx, "tools/call", params)
            rctx.tool = params.name
            rctx.escalate("error", f"unknown tool {params.name!r}")
            rctx.error_code = INVALID_PARAMS
            await _audit_miss(pipeline, rctx)
            raise MCPError(INVALID_PARAMS, f"Unknown tool: {params.name}")

        server_id, tool_name = parts
        rctx = new_ctx(ctx, "tools/call", params)
        rctx.server_id, rctx.tool, rctx.upstream_tool = server_id, params.name, tool_name
        arguments = params.arguments or {}
        tool_def = up.tools.get(tool_name)
        if tool_def is not None:
            rctx.input_schema = tool_def.input_schema
            rctx.destructive_hint = tool_def.annotations.destructive_hint if tool_def.annotations else None
        if approver is not None:
            approver.prepare_retry(rctx, params)

        async def forward() -> types.CallToolResult:
            if up.client is None:
                rctx.escalate("error", f"upstream {server_id!r} is unavailable ({up.last_error or 'down'})")
                rctx.add_finding(Finding(stage="upstream", rule_id="upstream.unavailable", severity="medium"))
                return pipeline.denial(rctx)

            async def relay_progress(progress: float, total: float | None, message: str | None) -> None:
                await ctx.session.report_progress(progress, total, message)

            try:
                result = await up.client.call_tool(
                    tool_name, arguments, read_timeout_seconds=up.timeout_s, progress_callback=relay_progress
                )
            except MCPError as e:
                rctx.error_code = e.error.code
                rctx.escalate("error", f"upstream {server_id!r} returned an error: {e.error.message}")
                result = pipeline.denial(rctx)
            except TimeoutError:
                rctx.escalate("error", f"upstream {server_id!r} timed out after {up.timeout_s:g}s")
                result = pipeline.denial(rctx)
            for ev in pool.drain_backchannel(server_id):
                rctx.add_finding(
                    Finding(
                        stage="passthrough",
                        rule_id="passthrough.backchannel_refused",
                        severity="low",
                        target=ev.method,
                    )
                )
            return result

        async def approve(c: RequestContext) -> types.InputRequiredResult | None:
            assert approver is not None
            return await approver.check(c, ctx, params, c.approval_reason or "approval required")

        result = await pipeline.call_tool(rctx, forward, approve if approver is not None else None)
        if (
            guard is not None
            and tool_def is not None
            and rctx.verdict == "approved"
            and guard.get(server_id, tool_name).status == "changed"
        ):
            guard.accept_change(server_id, tool_name, tool_def)  # the human accepted the new definition
        return result

    # -- resources ------------------------------------------------------------------

    async def on_list_resources(
        ctx: ServerRequestContext[Any], params: types.PaginatedRequestParams | None
    ) -> types.ListResourcesResult:
        rctx = new_ctx(ctx, "resources/list", params)

        async def run() -> types.ListResourcesResult:
            return types.ListResourcesResult(
                resources=[router.namespaced_resource(sid, r) for sid, r in pool.all_resources()]
            )

        async def measure(result: types.ListResourcesResult) -> TokenUsage:
            return meter.usage(schema=await meter.definitions_tokens(result.resources))

        result: types.ListResourcesResult = await pipeline.observe(rctx, run, measure)
        return result

    async def on_list_resource_templates(
        ctx: ServerRequestContext[Any], params: types.PaginatedRequestParams | None
    ) -> types.ListResourceTemplatesResult:
        rctx = new_ctx(ctx, "resources/templates/list", params)

        async def run() -> types.ListResourceTemplatesResult:
            return types.ListResourceTemplatesResult(
                resource_templates=[router.namespaced_template(sid, t) for sid, t in pool.all_templates()]
            )

        async def measure(result: types.ListResourceTemplatesResult) -> TokenUsage:
            return meter.usage(schema=await meter.definitions_tokens(result.resource_templates))

        result: types.ListResourceTemplatesResult = await pipeline.observe(rctx, run, measure)
        return result

    async def on_read_resource(
        ctx: ServerRequestContext[Any], params: types.ReadResourceRequestParams
    ) -> types.ReadResourceResult:
        uri = str(params.uri)
        rctx = new_ctx(ctx, "resources/read", params)
        owner = pool.resource_owner(uri)
        rctx.server_id = owner
        up = pool.get(owner) if owner else None

        async def run() -> types.ReadResourceResult:
            if up is None or up.client is None:
                raise MCPError(INVALID_PARAMS, f"Resource not found: {uri}", {"uri": uri})
            return await up.client.read_resource(uri)

        async def measure(result: types.ReadResourceResult) -> TokenUsage:
            return meter.usage(response=await meter.resource_contents_tokens(result.contents))

        result: types.ReadResourceResult = await pipeline.observe(rctx, run, measure)
        return result

    # -- prompts --------------------------------------------------------------------

    async def on_list_prompts(
        ctx: ServerRequestContext[Any], params: types.PaginatedRequestParams | None
    ) -> types.ListPromptsResult:
        rctx = new_ctx(ctx, "prompts/list", params)

        async def run() -> types.ListPromptsResult:
            return types.ListPromptsResult(
                prompts=[router.namespaced_prompt(sid, p) for sid, p in pool.all_prompts()]
            )

        async def measure(result: types.ListPromptsResult) -> TokenUsage:
            return meter.usage(schema=await meter.definitions_tokens(result.prompts))

        result: types.ListPromptsResult = await pipeline.observe(rctx, run, measure)
        return result

    async def on_get_prompt(
        ctx: ServerRequestContext[Any], params: types.GetPromptRequestParams
    ) -> types.GetPromptResult:
        rctx = new_ctx(ctx, "prompts/get", params)
        parts = router.split(params.name)
        up = pool.get(parts[0]) if parts else None
        rctx.server_id = parts[0] if parts else None

        async def run() -> types.GetPromptResult:
            if parts is None or up is None or up.client is None or parts[1] not in up.prompts:
                raise MCPError(INVALID_PARAMS, f"Unknown prompt: {params.name}")
            return await up.client.get_prompt(parts[1], params.arguments)

        async def measure(result: types.GetPromptResult) -> TokenUsage:
            return meter.usage(response=await meter.prompt_tokens(result))

        result: types.GetPromptResult = await pipeline.observe(rctx, run, measure)
        return result

    server: Server[Any] = Server(
        "mcp-shield",
        version=__version__,
        title="MCP Shield",
        instructions=INSTRUCTIONS,
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
        on_list_resources=on_list_resources,
        on_list_resource_templates=on_list_resource_templates,
        on_read_resource=on_read_resource,
        on_list_prompts=on_list_prompts,
        on_get_prompt=on_get_prompt,
    )

    async def audit_rejected_state(ctx: ServerRequestContext[Any], call_next: CallNext) -> HandlerResult:
        """The SDK rejects forged/expired requestState before any handler runs; audit it anyway (MP-C2)."""
        try:
            return await call_next(ctx)
        except MCPError as e:
            if ctx.method == "tools/call" and "requestState" in e.error.message:
                raw = dict(ctx.params or {})
                rctx = RequestContext(
                    connection=tracker.for_request(ctx),
                    method="tools/call",
                    protocol_version=ctx.protocol_version,
                    jsonrpc_id=str(ctx.request_id) if ctx.request_id is not None else None,
                    params={"name": raw.get("name"), "arguments": raw.get("arguments")},
                    tool=str(raw.get("name")),
                    leg=2,
                )
                parts = router.split(str(raw.get("name") or ""))
                rctx.server_id = parts[0] if parts else None
                rctx.error_code = e.error.code
                rctx.add_finding(Finding(stage="approval", rule_id="approval.state_invalid", severity="high"))
                rctx.escalate("denied", "invalid or expired approval state")
                await _audit_miss(pipeline, rctx)
            raise

    if approver is not None:
        # Outer: audit what the boundary rejects. Inner: seal/verify approval state (2026-07-28).
        server.middleware.append(audit_rejected_state)
        ttl = max(600.0, approver.ttl_s * 2)  # Shield enforces its own (audited) expiry first
        server.middleware.append(
            RequestStateBoundary(RequestStateSecurity.ephemeral(ttl=ttl), default_audience=server.name)
        )
    return server


async def notify_list_changed(tracker: ConnectionTracker, kind: str) -> None:
    """Tell connected clients an aggregated listing changed (best effort per session)."""
    for session in tracker.sessions():
        try:
            if kind == "tools":
                await session.send_tool_list_changed()
            elif kind == "resources":
                await session.send_resource_list_changed()
            elif kind == "prompts":
                await session.send_prompt_list_changed()
        except Exception as e:  # e.g. a 2026-07-28 connection without a listen stream
            log.debug("could not notify a session of %s change: %s", kind, e)


async def _audit_miss(pipeline: Pipeline, rctx: RequestContext) -> None:
    async def run() -> None:
        return None

    async def measure(_: Any) -> TokenUsage:
        return pipeline.meter.usage(
            request=await pipeline.meter.request_tokens((rctx.params or {}).get("arguments"))
        )

    await pipeline.observe(rctx, run, measure)


def _client_info(ctx: ServerRequestContext[Any]) -> tuple[str | None, str | None]:
    meta = ctx.meta
    info: Any = None
    if meta is not None:
        raw = meta if isinstance(meta, dict) else meta.model_dump(by_alias=True)
        info = raw.get(CLIENT_INFO_META_KEY)
    if info is None and ctx.session.client_params is not None:
        info = ctx.session.client_params.client_info
    if info is None:
        return None, None
    if isinstance(info, dict):
        return info.get("name"), info.get("version")
    return getattr(info, "name", None), getattr(info, "version", None)
