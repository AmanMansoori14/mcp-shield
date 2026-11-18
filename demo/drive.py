"""Drive Shield exactly like an MCP host would: launch ``shield run`` over stdio and make calls.

    uv run python -m demo.drive examples/shield.yaml                      # stdio
    SHIELD_TOKEN=... uv run python -m demo.drive http://127.0.0.1:8765/mcp  # Streamable HTTP

The example config connects a benign server (``notes``) and a deliberately malicious one
(``evil``), so the run shows each protection in turn.
"""

from __future__ import annotations

import os
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import anyio
import httpx2
from mcp import Client, StdioServerParameters, types
from mcp.client.streamable_http import streamable_http_client


async def approve_in_demo(context: Any, params: types.ElicitRequestParams) -> types.ElicitResult:
    print(f"   ↳ approval prompt: {params.message}")  # type: ignore[union-attr]
    print("   ↳ (demo auto-approves)")
    return types.ElicitResult(action="accept", content={"approve": True})


def show(label: str, result: types.CallToolResult) -> None:
    text = " ".join(getattr(c, "text", "") for c in result.content).replace("\n", " ")
    flag = "ERROR" if result.is_error else "ok"
    print(f"{label:<44} → {flag:<5} {text[:110]}{'…' if len(text) > 110 else ''}")


def target(arg: str) -> tuple[Any, str]:
    """A shield.yaml path → launch `shield run` over stdio; an http(s) URL → Streamable HTTP with SHIELD_TOKEN."""
    if not arg.startswith(("http://", "https://")):
        return StdioServerParameters(command="uv", args=["run", "shield", "run", "--config", arg]), "stdio"

    @asynccontextmanager
    async def http() -> AsyncIterator[Any]:
        headers = {"Authorization": f"Bearer {os.environ['SHIELD_TOKEN']}"}
        async with (
            httpx2.AsyncClient(headers=headers, timeout=60) as session,
            streamable_http_client(arg, http_client=session) as streams,
        ):
            yield streams

    return http(), "HTTP"


async def main(arg: str) -> None:
    shield, transport = target(arg)
    async with Client(shield, elicitation_callback=approve_in_demo) as client:
        print(f"connected over {transport} · protocol {client.protocol_version}\n")

        tools = sorted(t.name for t in (await client.list_tools()).tools)
        print(f"tools/list → {len(tools)} visible: {', '.join(tools)}")
        print("   (evil__get_weather and evil__translate are hidden: poisoned descriptions)\n")

        steps: list[tuple[str, str, dict[str, Any]]] = [
            ("1. normal call", "notes__add", {"a": 20, "b": 22}),
            ("2. token-heavy output (audited)", "notes__read_note", {"name": "big"}),
            ("3. call a hidden poisoned tool", "evil__get_weather", {"city": "Paris"}),
            ("4. result injection + leaked AWS key", "evil__fetch_page", {"url": "https://docs.example"}),
            ("5. path traversal in arguments", "notes__echo", {"text": "../../etc/passwd"}),
            ("6. arguments that break the schema", "notes__add", {"a": "twenty", "b": 22}),
            ("7. destructive tool (needs approval)", "evil__delete_note", {"name": "todo"}),
        ]
        for label, name, args in steps:
            show(label, await client.call_tool(name, args))


if __name__ == "__main__":
    anyio.run(main, sys.argv[1] if len(sys.argv) > 1 else "examples/shield.yaml")
