"""Upstreams that misbehave in protocol-level ways Shield must survive (IP-A11, IP-A13).

* ``make_bad_names()``  - valid schemas, but tool names Shield can't re-expose once prefixed
                          (too long, or characters outside ``[A-Za-z0-9_.-]``). Dropped per tool.
* ``make_broken_listing()`` - a tool with an invalid input schema. SDK v2 refuses to send (and to
                          receive) that listing, so the whole upstream is marked degraded while
                          every other upstream keeps working.
* ``asks_user``         - a tool that tries to ask the client for input (elicitation). Shield
                          refuses it in v1 and records ``passthrough.backchannel_refused``.
"""

from __future__ import annotations

from typing import Annotated, Any

from mcp import types
from mcp.server import MCPServer, Server, ServerRequestContext
from mcp.server.mcpserver import AcceptedElicitation, Elicit, ElicitationResult, Resolve
from pydantic import BaseModel

_OBJ: dict[str, Any] = {"type": "object", "properties": {}}


def _server(name: str, tools: list[types.Tool]) -> Server[Any]:
    async def list_tools(
        ctx: ServerRequestContext[Any], params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        return types.ListToolsResult.model_construct(tools=tools)

    async def call_tool(
        ctx: ServerRequestContext[Any], params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        return types.CallToolResult(content=[types.TextContent(type="text", text=f"called {params.name}")])

    return Server(name, on_list_tools=list_tools, on_call_tool=call_tool)


def make_bad_names() -> Server[Any]:
    return _server(
        "bad-names",
        [
            types.Tool(name="ok", description="A valid tool.", input_schema=_OBJ),
            types.Tool(name="x" * 125, description="Too long once prefixed.", input_schema=_OBJ),
            types.Tool(name="has space!", description="Invalid characters.", input_schema=_OBJ),
        ],
    )


def make_broken_listing() -> Server[Any]:
    return _server(
        "broken",
        [
            types.Tool.model_construct(
                name="bad_schema", description="Schema is not an object.", input_schema={"type": "string"}
            ),
        ],
    )


# --------------------------------------------------------------------------- asks_user

asks_user = MCPServer("asks-user")


class Confirm(BaseModel):
    ok: bool


async def _ask() -> Elicit[Confirm]:
    return Elicit("Shall I proceed?", Confirm)


@asks_user.tool()
async def needs_confirmation(answer: Annotated[ElicitationResult[Confirm], Resolve(_ask)]) -> str:
    """A tool that asks the user before running."""
    if isinstance(answer, AcceptedElicitation) and answer.data.ok:
        return "confirmed"
    return "not confirmed"
