"""Streamable HTTP face (TS-C6, IP-A14).

* Bearer token (``SHIELD_TOKEN``) checked in constant time before anything reaches MCP.
* DNS-rebinding protection: ``Host`` and ``Origin`` allowlists (the SDK's transport security).
* Binds to ``127.0.0.1`` by default.
* The client's token is never forwarded upstream (MP-C8): upstream connections carry only
  the credentials configured for them in ``servers.yaml``.
"""

from __future__ import annotations

import hmac
import json
from typing import Any

from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.types import ASGIApp, Receive, Scope, Send

from mcp_shield.app import Shield


class BearerAuth:
    """Pure ASGI middleware (keeps streaming responses intact)."""

    def __init__(self, app: ASGIApp, token: str, path: str = "/mcp"):
        if len(token) < 16:
            raise ValueError("SHIELD_TOKEN must be at least 16 characters")
        self.app, self.token, self.path = app, token.encode(), path

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["path"].startswith(self.path):
            auth = dict(scope.get("headers") or []).get(b"authorization", b"")
            if not (auth.startswith(b"Bearer ") and hmac.compare_digest(auth[7:], self.token)):
                body = json.dumps(
                    {"error": "unauthorized", "hint": "send Authorization: Bearer <SHIELD_TOKEN>"}
                )
                await send(
                    {
                        "type": "http.response.start",
                        "status": 401,
                        "headers": [
                            (b"content-type", b"application/json"),
                            (b"www-authenticate", b'Bearer realm="mcp-shield"'),
                        ],
                    }
                )
                await send({"type": "http.response.body", "body": body.encode()})
                return
        await self.app(scope, receive, send)


def build_http_app(
    shield: Shield,
    *,
    token: str,
    host: str = "127.0.0.1",
    port: int = 8765,
    extra_origins: list[str] | None = None,
    extra_hosts: list[str] | None = None,
) -> Any:
    """``extra_hosts`` admits other ``Host`` headers, e.g. ``shield:8765`` inside a Docker network."""
    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[f"{host}:{port}", f"127.0.0.1:{port}", f"localhost:{port}", *(extra_hosts or [])],
        allowed_origins=[
            f"http://{host}:{port}",
            f"http://127.0.0.1:{port}",
            f"http://localhost:{port}",
            *(extra_origins or []),
        ],
    )
    app: Starlette = shield.server.streamable_http_app(host=host, transport_security=security)
    return BearerAuth(app, token)


async def serve_http(
    shield: Shield,
    *,
    token: str,
    host: str = "127.0.0.1",
    port: int = 8765,
    extra_hosts: list[str] | None = None,
) -> None:
    import uvicorn

    app = build_http_app(shield, token=token, host=host, port=port, extra_hosts=extra_hosts)
    config = uvicorn.Config(app, host=host, port=port, log_level="warning", lifespan="on")
    async with shield.running():
        await uvicorn.Server(config).serve()
