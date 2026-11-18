"""Drive Shield exactly like an MCP host would: launch ``shield run`` over stdio and make calls.

uv run python -m demo.drive examples/shield.yaml
"""

from __future__ import annotations

import sys

import anyio
from mcp import Client, StdioServerParameters


async def main(config: str) -> None:
    shield = StdioServerParameters(command="uv", args=["run", "shield", "run", "--config", config])
    async with Client(shield) as client:
        print(
            f"connected to {client.server_info.name if client.server_info else 'shield'} "
            f"over stdio · protocol {client.protocol_version}\n"
        )

        tools = (await client.list_tools()).tools
        print(f"tools/list → {len(tools)} tools: {', '.join(t.name for t in tools)}")

        steps: list[tuple[str, dict[str, object]]] = [
            ("notes__echo", {"text": "hello through the shield"}),
            ("notes__add", {"a": 20, "b": 22}),
            ("notes__read_note", {"name": "big"}),  # token-heavy output
            ("notes__add", {"a": "twenty", "b": 22}),  # blocked: arguments don't match the schema
            ("notes__read_note", {"name": "missing"}),  # the upstream tool's own error
        ]
        for name, args in steps:
            result = await client.call_tool(name, args)
            text = " ".join(getattr(c, "text", "") for c in result.content)
            flag = "ERROR" if result.is_error else "ok"
            print(f"tools/call {name:<18} → {flag:<5} {text[:90]}{'…' if len(text) > 90 else ''}")


if __name__ == "__main__":
    anyio.run(main, sys.argv[1] if len(sys.argv) > 1 else "examples/shield.yaml")
