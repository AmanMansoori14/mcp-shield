"""TS-C6: Streamable HTTP face - auth, DNS-rebinding protection, grouping - and HTTP upstreams (MP-C8)."""

from __future__ import annotations

import socket
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import anyio
import httpx2
import pytest
import uvicorn
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.server import MCPServer

from demo.benign_server import mcp as notes
from mcp_shield.app import Shield
from mcp_shield.config import HttpServer
from mcp_shield.http_face import BearerAuth, build_http_app
from mcp_shield.metering.tokenizer import CharHeuristicTokenizer
from mcp_shield.proxy.upstream_pool import Upstream, target_for

pytestmark = pytest.mark.anyio
TOKEN = "test-token-0123456789abcdef"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@asynccontextmanager
async def serve(app: Any, port: int) -> AsyncIterator[None]:
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error", lifespan="on")
    )
    async with anyio.create_task_group() as tg:
        tg.start_soon(server.serve)
        with anyio.fail_after(10):
            while not server.started:  # noqa: ASYNC110 - uvicorn exposes no event to wait on
                await anyio.sleep(0.02)
        try:
            yield
        finally:
            server.should_exit = True


@asynccontextmanager
async def shield_http(tmp_path: Path, upstreams: list[Upstream]) -> AsyncIterator[tuple[Shield, str]]:
    port = free_port()
    shield = Shield(
        upstreams,
        db_path=tmp_path / "a.db",
        spool_path=tmp_path / "s.jsonl",
        tokenizer=CharHeuristicTokenizer(),
        connection_kind="http",
        retention_days=None,
    )
    app = build_http_app(shield, token=TOKEN, port=port)
    async with shield.running(), serve(app, port):
        yield shield, f"http://127.0.0.1:{port}/mcp"


def authed(url: str, token: str = TOKEN) -> Any:
    @asynccontextmanager
    async def transport() -> AsyncIterator[Any]:
        async with (
            httpx2.AsyncClient(headers={"Authorization": f"Bearer {token}"}) as http,
            streamable_http_client(url, http_client=http) as streams,
        ):
            yield streams

    return transport()


def in_process(server: Any, sid: str = "notes") -> Upstream:
    return Upstream(id=sid, transport="in_process", target=server)


async def test_requires_bearer_token(tmp_path: Path) -> None:
    async with shield_http(tmp_path, [in_process(notes)]) as (_, url), httpx2.AsyncClient() as http:
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        none = await http.post(url, json=body)
        wrong = await http.post(url, json=body, headers={"Authorization": "Bearer nope"})
    assert none.status_code == 401 and wrong.status_code == 401
    assert none.headers["www-authenticate"].startswith("Bearer")


async def test_foreign_origin_is_rejected(tmp_path: Path) -> None:
    async with shield_http(tmp_path, [in_process(notes)]) as (_, url), httpx2.AsyncClient() as http:
        r = await http.post(
            url,
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={
                "Authorization": f"Bearer {TOKEN}",
                "Origin": "http://evil.example",
                "Accept": "application/json, text/event-stream",
            },
        )
    assert r.status_code in (400, 403)  # DNS-rebinding protection (SDK transport security)


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_tool_calls_over_http_and_connection_kinds(tmp_path: Path, mode: str) -> None:
    async with (
        shield_http(tmp_path, [in_process(notes)]) as (shield, url),
        Client(authed(url), mode=mode) as client,  # type: ignore[arg-type]
    ):
        for i in range(3):
            result = await client.call_tool("notes__echo", {"text": f"http {i}"})
            assert result.content[0].text == f"http {i}"  # type: ignore[union-attr]
        version = client.protocol_version
    kinds = shield.store.query("SELECT kind, COUNT(*) n FROM connections GROUP BY kind")
    expected = "grouped" if version >= "2026-07-28" else "legacy_session"
    assert kinds == [{"kind": expected, "n": 1}]  # three requests, one connection
    assert (
        shield.store.scalar("SELECT COUNT(DISTINCT connection_id) FROM requests WHERE method='tools/call'")
        == 1
    )


async def test_client_token_is_never_forwarded_to_http_upstreams(tmp_path: Path) -> None:
    seen: list[dict[str, str]] = []
    upstream = MCPServer("remote")

    @upstream.tool()
    def ping_remote() -> str:
        """Answer from the remote server."""
        return "pong"

    inner = upstream.streamable_http_app()

    async def capture(scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] == "http":
            seen.append({k.decode(): v.decode() for k, v in scope["headers"]})
        await inner(scope, receive, send)

    up_port = free_port()
    cfg = HttpServer(
        id="remote",
        transport="http",
        url=f"http://127.0.0.1:{up_port}/mcp",
        headers={"X-Upstream-Key": "upstream-own-secret"},
    )
    async with serve(capture, up_port):
        remote = Upstream(id="remote", transport="http", target=target_for(cfg), timeout_s=10)
        async with (
            shield_http(tmp_path, [remote]) as (_, url),
            Client(authed(url)) as client,  # type: ignore[arg-type]
        ):
            result = await client.call_tool("remote__ping_remote", {})
    assert result.content[0].text == "pong"  # type: ignore[union-attr]
    assert seen and all(h.get("x-upstream-key") == "upstream-own-secret" for h in seen)
    assert not any(TOKEN in v for h in seen for v in h.values())  # MP-C8


def test_short_tokens_are_refused() -> None:
    async def app(scope: Any, receive: Any, send: Any) -> None:
        pass

    with pytest.raises(ValueError, match="at least 16"):
        BearerAuth(app, "short")
