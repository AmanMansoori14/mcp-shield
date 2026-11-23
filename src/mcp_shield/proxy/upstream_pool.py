"""Upstream connector pool: Shield as an MCP *client* to N servers (IP-A2, TS-A3).

* One SDK ``Client`` per upstream, keyed by its ``servers.yaml`` id (MP-C9).
* Each upstream is isolated: a crash, timeout, or malformed response from one
  never breaks the others (IP-A13).
* Listings are validated; tools that would make Shield's own ``tools/list``
  invalid are dropped and reported (IP-A13).
* Requests an upstream sends *to the client* (elicitation, sampling, roots) are
  refused and recorded (IP-A11). Response caching is off so Shield always sees
  the live definitions.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

import anyio
import httpx2
from anyio.abc import TaskGroup
from mcp import Client, MCPError, StdioServerParameters, types
from mcp.client.context import ClientRequestContext
from mcp.client.session import IncomingMessage
from mcp.client.streamable_http import streamable_http_client
from mcp.server import Server
from mcp.types import CONNECTION_CLOSED

from mcp_shield import __version__
from mcp_shield.config import HttpServer, ServerConfig, StdioServer
from mcp_shield.proxy import router

log = logging.getLogger(__name__)

Target = Server[Any] | StdioServerParameters | str | Any  # Any: a Transport context manager


@dataclass
class BackchannelEvent:
    server_id: str
    method: str
    at: float = field(default_factory=time.monotonic)


@dataclass
class Upstream:
    id: str
    transport: str
    target: Target
    timeout_s: float = 30.0
    client: Client | None = None
    status: str = "down"
    last_error: str | None = None
    protocol_version: str | None = None
    tools: dict[str, types.Tool] = field(default_factory=dict)
    resources: dict[str, types.Resource] = field(default_factory=dict)
    templates: list[types.ResourceTemplate] = field(default_factory=list)
    prompts: dict[str, types.Prompt] = field(default_factory=dict)
    dropped: list[dict[str, str]] = field(default_factory=list)
    stop: anyio.Event | None = None
    wake: anyio.Event | None = None  # set on stop, or when a call finds the connection dead
    restarts: int = 0


ChangeCallback = Callable[[str, str], Awaitable[None]]  # (server_id, kind: tools|resources|prompts)


def target_for(cfg: ServerConfig) -> Target:
    """Build an SDK client target from a ``servers.yaml`` entry."""
    if isinstance(cfg, StdioServer):
        return StdioServerParameters(
            command=cfg.command[0], args=list(cfg.command[1:]), env=cfg.env or None, cwd=cfg.cwd
        )
    assert isinstance(cfg, HttpServer)
    return _http_transport(cfg.url, dict(cfg.headers), cfg.timeout_s)


@asynccontextmanager
async def _http_transport_cm(url: str, headers: dict[str, str], timeout_s: float) -> AsyncIterator[Any]:
    # The upstream's own credentials only - the client's token is never forwarded (MP-C8).
    async with (
        httpx2.AsyncClient(headers=headers, timeout=httpx2.Timeout(timeout_s, read=300.0)) as http,
        streamable_http_client(url, http_client=http) as streams,
    ):
        yield streams


class _HttpTransportFactory:
    """Callable target: a fresh transport per (re)connect."""

    def __init__(self, url: str, headers: dict[str, str], timeout_s: float):
        self.url, self.headers, self.timeout_s = url, headers, timeout_s

    def __call__(self) -> Any:
        return _http_transport_cm(self.url, self.headers, self.timeout_s)


def _http_transport(url: str, headers: dict[str, str], timeout_s: float) -> _HttpTransportFactory:
    return _HttpTransportFactory(url, headers, timeout_s)


class UpstreamPool:
    def __init__(
        self,
        upstreams: list[Upstream],
        on_change: ChangeCallback | None = None,
        *,
        max_restarts: int = 3,
        backoff_s: float = 1.0,
    ):
        self.upstreams: dict[str, Upstream] = {u.id: u for u in upstreams}
        self.on_change = on_change
        self.max_restarts = max_restarts
        self.backoff_s = backoff_s
        self.backchannel: list[BackchannelEvent] = []
        self._tg: TaskGroup | None = None

    @classmethod
    def from_config(
        cls, servers: list[ServerConfig], on_change: ChangeCallback | None = None
    ) -> UpstreamPool:
        return cls(
            [
                Upstream(id=s.id, transport=s.transport, target=target_for(s), timeout_s=s.timeout_s)
                for s in servers
            ],
            on_change,
        )

    # -- lifecycle ---------------------------------------------------------

    async def start(self, tg: TaskGroup) -> None:
        """Connect every upstream concurrently; returns once each is up or has failed.

        Each upstream lives in its own task in ``tg``: anyio requires a client's context
        to be exited by the same task that entered it.
        """
        self._tg = tg
        ready = {up.id: anyio.Event() for up in self.upstreams.values()}
        for up in self.upstreams.values():
            up.stop = anyio.Event()
            tg.start_soon(self._run, up, ready[up.id])
        for ev in ready.values():
            await ev.wait()

    async def aclose(self) -> None:
        for up in self.upstreams.values():
            if up.stop is not None:
                up.stop.set()
            if up.wake is not None:
                up.wake.set()

    def mark_failed(self, server_id: str, reason: str) -> None:
        """A call or listing found the connection dead: wake the session so it reconnects (gap #17)."""
        up = self.upstreams.get(server_id)
        if up is None or up.wake is None or up.wake.is_set():
            return
        log.warning("upstream %s connection lost: %s", server_id, reason)
        up.status, up.last_error = "degraded", reason
        up.wake.set()

    async def _run(self, up: Upstream, ready: anyio.Event) -> None:
        """Keep one upstream connected: reconnect with exponential backoff after a crash (gap #17).

        After ``max_restarts`` consecutive failed connection attempts the upstream stays
        ``down``; a successful connection resets the counter. Backoff doubles each time.
        """
        failures = 0  # consecutive attempts that failed to connect
        while True:
            connected, stopped = await self._session(up, ready, reconnect=up.restarts > 0)
            if stopped:
                return
            failures = 0 if connected else failures + 1
            if failures >= self.max_restarts:
                log.error(
                    "upstream %s: giving up after %d failed attempts: %s", up.id, failures, up.last_error
                )
                return
            delay = self.backoff_s * (2**failures)
            log.warning("upstream %s: reconnecting in %.1fs", up.id, delay)
            assert up.stop is not None
            with anyio.move_on_after(delay):
                await up.stop.wait()
            if up.stop.is_set():
                return
            up.restarts += 1

    async def _session(self, up: Upstream, ready: anyio.Event, *, reconnect: bool) -> tuple[bool, bool]:
        """One connection lifetime. Returns ``(connected, stopped_cleanly)``."""
        connected = False
        up.wake = anyio.Event()
        try:
            target = up.target() if isinstance(up.target, _HttpTransportFactory) else up.target
            client = Client(
                target,
                client_info=types.Implementation(name="mcp-shield", version=__version__),
                cache=None,
                read_timeout_seconds=up.timeout_s,
                elicitation_callback=self._refuse_elicitation(up.id),
                message_handler=self._message_handler(up.id),
            )
            async with AsyncExitStack() as stack:
                # No fail_after here: the client opens its own cancel scope on enter, which must
                # not be nested inside a scope we exit first. read_timeout_seconds bounds the probe.
                up.client = await stack.enter_async_context(client)
                connected = True
                up.protocol_version = client.protocol_version
                up.status, up.last_error = "up", None
                await self.refresh(up.id)
                ready.set()
                if reconnect:
                    log.info("upstream %s reconnected", up.id)
                    if self.on_change is not None:
                        await self.on_change(up.id, "tools")
                await up.wake.wait()
                if up.stop is None or not up.stop.is_set():
                    raise ConnectionError(up.last_error or "connection lost")
            return connected, True
        except Exception as e:  # includes ExceptionGroup from a crashed transport
            up.last_error = _describe(e)
            log.warning("upstream %s is down: %s", up.id, up.last_error)
            return connected, bool(up.stop and up.stop.is_set())
        finally:
            up.client, up.status = None, "down"
            ready.set()

    # -- listings ----------------------------------------------------------

    async def refresh(self, server_id: str) -> None:
        """Re-list one upstream's tools/resources/prompts, validating every tool."""
        up = self.upstreams[server_id]
        client = up.client
        if client is None:
            return
        caps = client.server_capabilities
        try:
            if caps.tools is not None:
                tools = await _all_pages(lambda c: client.list_tools(cursor=c), "tools")
                up.tools, up.dropped = {}, []
                for t in tools:
                    problem = router.tool_problem(up.id, t)
                    if problem:
                        up.dropped.append({"name": t.name, "reason": problem})
                    else:
                        up.tools[t.name] = t
            if caps.resources is not None:
                res = await _all_pages(lambda c: client.list_resources(cursor=c), "resources")
                up.resources = {str(r.uri): r for r in res}
                up.templates = await _all_pages(
                    lambda c: client.list_resource_templates(cursor=c), "resource_templates"
                )
            if caps.prompts is not None:
                prompts = await _all_pages(lambda c: client.list_prompts(cursor=c), "prompts")
                up.prompts = {p.name: p for p in prompts}
            up.status, up.last_error = "up", None
        except Exception as e:
            up.status, up.last_error = "degraded", _describe(e)
            log.warning("upstream %s listing failed: %s", up.id, up.last_error)
            if is_connection_lost(e):
                self.mark_failed(up.id, up.last_error)

    def all_tools(self) -> list[tuple[str, types.Tool]]:
        return [(up.id, t) for up in self.upstreams.values() if up.client for t in up.tools.values()]

    def all_resources(self) -> list[tuple[str, types.Resource]]:
        seen: set[str] = set()
        out: list[tuple[str, types.Resource]] = []
        for up in self.upstreams.values():
            for uri, r in up.resources.items():
                if uri not in seen:  # first upstream wins a URI collision
                    seen.add(uri)
                    out.append((up.id, r))
        return out

    def all_templates(self) -> list[tuple[str, types.ResourceTemplate]]:
        return [(up.id, t) for up in self.upstreams.values() if up.client for t in up.templates]

    def all_prompts(self) -> list[tuple[str, types.Prompt]]:
        return [(up.id, p) for up in self.upstreams.values() if up.client for p in up.prompts.values()]

    def resource_owner(self, uri: str) -> str | None:
        for up in self.upstreams.values():
            if uri in up.resources:
                return up.id
        for up in self.upstreams.values():
            for tpl in up.templates:
                if template_regex(tpl.uri_template).fullmatch(uri):
                    return up.id
        return None

    def get(self, server_id: str) -> Upstream | None:
        return self.upstreams.get(server_id)

    def drain_backchannel(self, server_id: str) -> list[BackchannelEvent]:
        mine = [e for e in self.backchannel if e.server_id == server_id]
        self.backchannel = [e for e in self.backchannel if e.server_id != server_id]
        return mine

    # -- upstream → client traffic -------------------------------------------

    def _refuse_elicitation(self, server_id: str) -> Any:
        async def callback(
            context: ClientRequestContext, params: types.ElicitRequestParams
        ) -> types.ErrorData:
            self.backchannel.append(BackchannelEvent(server_id, "elicitation/create"))
            return types.ErrorData(
                code=types.INVALID_REQUEST,
                message="MCP Shield does not relay elicitation from upstream servers (v1).",
            )

        return callback

    def _message_handler(self, server_id: str) -> Any:
        async def handler(message: IncomingMessage) -> None:
            if isinstance(message, Exception):
                log.warning("upstream %s transport error: %s", server_id, message)
                return
            kind = {
                types.ToolListChangedNotification: "tools",
                types.ResourceListChangedNotification: "resources",
                types.PromptListChangedNotification: "prompts",
            }.get(type(message))
            if kind and self._tg is not None:
                self._tg.start_soon(self._on_list_changed, server_id, kind)

        return handler

    async def _on_list_changed(self, server_id: str, kind: str) -> None:
        await self.refresh(server_id)
        if self.on_change is not None:
            await self.on_change(server_id, kind)


async def _all_pages(
    fetch: Callable[[str | None], Awaitable[Any]], attr: str, max_pages: int = 50
) -> list[Any]:
    items: list[Any] = []
    cursor: str | None = None
    for _ in range(max_pages):
        page = await fetch(cursor)
        items.extend(getattr(page, attr))
        cursor = page.next_cursor
        if not cursor:
            break
    return items


def is_connection_lost(e: BaseException) -> bool:
    if isinstance(e, MCPError):
        return e.error.code == CONNECTION_CLOSED
    return isinstance(
        e, (ConnectionError, anyio.ClosedResourceError, anyio.BrokenResourceError, anyio.EndOfStream)
    )


def _describe(e: BaseException) -> str:
    if isinstance(e, BaseExceptionGroup) and e.exceptions:
        return _describe(e.exceptions[0])
    return f"{type(e).__name__}: {e}" if str(e) else type(e).__name__


_SEGMENT = r"[^/?#,]+"
_EXPANSIONS = {  # RFC 6570 operator -> (prefix, one value, separator for lists/explode)
    "": ("", _SEGMENT, ","),
    "+": ("", r"[^?#]+", ","),
    "#": ("#", r".+", ","),
    ".": (r"\.", r"[^/?#.,]+", r"\."),
    "/": ("/", _SEGMENT, "/"),
    ";": (";", r"[^/?#;]+", ";"),
    "?": (r"\?", r"[^#&]+", "&"),
    "&": ("&", r"[^#&]+", "&"),
}


@lru_cache(maxsize=512)
def template_regex(template: str) -> re.Pattern[str]:
    """A regex for the URIs an RFC 6570 template can produce. A plain ``{path}`` matches one
    segment (no ``/``), as simple expansion percent-encodes ``/``; ``{+path}`` or ``{/path*}``
    are how a template opts in to multi-segment values. Unknown syntax matches nothing extra."""
    out, pos = [], 0
    for m in re.finditer(r"\{([^}]*)\}", template):
        out.append(re.escape(template[pos : m.start()]))
        expr = m.group(1)
        op = expr[0] if expr[:1] in _EXPANSIONS and expr[:1] != "" else ""
        names = expr[len(op) :].split(",")
        prefix, value, sep = _EXPANSIONS[op]
        exploded = any(n.endswith("*") for n in names)
        many = len(names) > 1 or exploded
        body = f"{value}(?:{sep}{value})*" if many else value
        out.append(f"(?:{prefix}{body})?" if op in ("?", "&", "#", ";") else f"{prefix}{body}")
        pos = m.end()
    out.append(re.escape(template[pos:]))
    return re.compile("".join(out))
