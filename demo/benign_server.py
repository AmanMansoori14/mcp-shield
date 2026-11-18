"""A well-behaved demo MCP server: notes, maths, a slow task with progress, a resource and a prompt.

Run standalone:  uv run python -m demo.benign_server
"""

from __future__ import annotations

from typing import Annotated

import anyio
from mcp.server import MCPServer
from mcp.server.mcpserver import Context
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import BaseModel, Field

mcp = MCPServer("notes", instructions="Demo notes server for MCP Shield.")

NOTES = {
    "welcome": "Welcome to MCP Shield. Every call you make through it is audited with its token cost.",
    "big": " ".join(["Token-heavy tool output can quietly eat your context window."] * 400),
}


class Sum(BaseModel):
    result: int


@mcp.tool()
def echo(text: Annotated[str, Field(description="Text to echo back")]) -> str:
    """Echo the text back unchanged."""
    return text


@mcp.tool()
def add(a: int, b: int) -> Sum:
    """Add two integers."""
    return Sum(result=a + b)


@mcp.tool()
def read_note(name: Annotated[str, Field(description="Note name, e.g. 'welcome' or 'big'")]) -> str:
    """Read a stored note by name."""
    if name not in NOTES:
        raise ToolError(f"no note named {name!r}; try one of {sorted(NOTES)}")
    return NOTES[name]


@mcp.tool()
async def slow_count(to: Annotated[int, Field(ge=1, le=20)], ctx: Context) -> str:
    """Count up slowly, reporting progress."""
    for i in range(1, to + 1):
        await ctx.report_progress(i, to, f"counted {i}")
        await anyio.sleep(0.01)
    return f"counted to {to}"


@mcp.resource("notes://welcome")
def welcome_note() -> str:
    """The welcome note as a resource."""
    return NOTES["welcome"]


@mcp.prompt()
def summarize_note(name: str) -> str:
    """Ask the model to summarise a note."""
    return f"Summarise the note called {name!r} in one sentence."


if __name__ == "__main__":
    mcp.run()
