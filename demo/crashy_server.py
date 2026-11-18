"""An upstream that can be made to crash, to show Shield reconnecting (gap #17).

Run standalone:  uv run python -m demo.crashy_server
"""

from __future__ import annotations

import os
import threading

from mcp.server import MCPServer

mcp = MCPServer("crashy")


@mcp.tool()
def echo(text: str) -> str:
    """Echo the text back."""
    return text


@mcp.tool()
def crash() -> str:
    """Exit the server process shortly after answering (simulates a crash)."""
    threading.Timer(0.2, lambda: os._exit(1)).start()
    return "crashing in 0.2s"


if __name__ == "__main__":
    mcp.run()
