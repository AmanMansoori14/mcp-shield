"""Namespacing and upstream-definition validation (IP-A12, IP-A13).

Aggregated names are ``{config_id}__{name}``. The prefix comes from ``servers.yaml``
only, never from the upstream's self-reported ``serverInfo`` (MP-C9). Config ids
can't contain ``__``, so the first ``__`` always splits a name unambiguously.
"""

from __future__ import annotations

import re
from typing import Any

from mcp import types

SEP = "__"
TOOL_NAME = re.compile(r"^[A-Za-z0-9_.\-]{1,128}$")


def prefixed(server_id: str, name: str) -> str:
    return f"{server_id}{SEP}{name}"


def split(name: str) -> tuple[str, str] | None:
    server_id, sep, rest = name.partition(SEP)
    if not sep or not server_id or not rest:
        return None
    return server_id, rest


def tool_problem(server_id: str, tool: types.Tool) -> str | None:
    """Why an upstream tool can't be re-exposed, or ``None`` if it's fine.

    SDK v2 validates Shield's *outgoing* ``tools/list``, so one malformed upstream tool
    would otherwise fail the whole aggregated listing for every server.
    """
    name = prefixed(server_id, tool.name)
    if not TOOL_NAME.match(name):
        if len(name) > 128:
            return f"prefixed name is {len(name)} characters (max 128)"
        return "name contains characters outside [A-Za-z0-9_.-]"
    if not _is_object_schema(tool.input_schema):
        return 'inputSchema must be a JSON Schema object with "type": "object"'
    if tool.output_schema is not None and not _is_object_schema(tool.output_schema):
        return 'outputSchema must be a JSON Schema object with "type": "object"'
    return None


def _is_object_schema(schema: Any) -> bool:
    return isinstance(schema, dict) and schema.get("type") == "object"


def namespaced_tool(server_id: str, tool: types.Tool) -> types.Tool:
    return tool.model_copy(update={"name": prefixed(server_id, tool.name)})


def namespaced_prompt(server_id: str, prompt: types.Prompt) -> types.Prompt:
    return prompt.model_copy(update={"name": prefixed(server_id, prompt.name)})


def namespaced_resource(server_id: str, resource: types.Resource) -> types.Resource:
    """Resources keep their URI (routing is by URI ownership); the display name is prefixed."""
    return resource.model_copy(update={"name": prefixed(server_id, resource.name)})


def namespaced_template(server_id: str, tpl: types.ResourceTemplate) -> types.ResourceTemplate:
    return tpl.model_copy(update={"name": prefixed(server_id, tpl.name)})
