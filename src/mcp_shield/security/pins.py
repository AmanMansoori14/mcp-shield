"""Tool pinning and definition screening (TS-B9, IP-A16, MP-B3).

Each upstream tool definition (name, description, schemas, annotations) is hashed the
first time Shield sees it. A later listing with a different hash is a rug-pull
candidate: the tool is re-scanned and flagged ``changed``; ``pinning.on_change``
decides whether it is only warned about, blocked, or needs approval on next use.

Descriptions are scanned on every listing; with ``scanner.description_action: block``
a poisoned tool is hidden from clients and any call to it is refused.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Literal

from mcp import types

from mcp_shield.audit.models import Finding, new_id, now_iso
from mcp_shield.audit.store import AuditStore
from mcp_shield.security.scanner import Scanner

Status = Literal["pinned", "changed", "hidden"]


def definition_hash(tool: types.Tool) -> str:
    d = tool.model_dump(mode="json", by_alias=True, exclude_none=True)
    d.pop("_meta", None)
    d.pop("icons", None)
    return hashlib.sha256(json.dumps(d, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass
class ToolState:
    status: Status = "pinned"
    findings: list[Finding] = field(default_factory=list)
    reason: str | None = None
    previous_description: str | None = None


class ToolGuard:
    """Per-tool security state shared by the server face (hidden / changed / clean)."""

    def __init__(self, store: AuditStore, scanner: Scanner):
        self.store = store
        self.scanner = scanner
        self.state: dict[tuple[str, str], ToolState] = {}
        self._pins = {(r["server_id"], r["tool"]): r for r in store.query("SELECT * FROM tool_pins")}
        self._descriptions: dict[tuple[str, str], str | None] = {}

    def screen(
        self,
        server_id: str,
        tools: list[types.Tool],
        *,
        description_action: str = "block",
        on_change: str = "require_approval",
    ) -> list[tuple[str, str]]:
        """Scan and pin one upstream's tools. Returns ``[(tool, event)]`` for new findings/changes."""
        events: list[tuple[str, str]] = []
        for tool in tools:
            key = (server_id, tool.name)
            h = definition_hash(tool)
            scan = self.scanner.scan_tool_definition(tool.name, tool.description, tool.input_schema)
            state = ToolState()
            pin = self._pins.get(key)
            if pin is None:
                self._write_pin(server_id, tool.name, h, "pinned", first=True)
            elif pin["def_hash"] != h:
                prev = self._descriptions.get(key)
                state.status = "changed"
                state.previous_description = prev
                state.reason = "its definition changed since it was first seen (possible rug-pull)"
                state.findings.append(
                    Finding(
                        stage="pinning",
                        rule_id="pinning.tool_changed",
                        severity="high",
                        target=tool.name,
                        excerpt_redacted=f"hash {pin['def_hash'][:12]} → {h[:12]}",
                    )
                )
                if pin["status"] != "changed":
                    events.append((tool.name, "changed"))
                # Keep the *old* hash pinned until a human accepts the change (or on_change=warn).
                if on_change == "warn":
                    self._write_pin(server_id, tool.name, h, "pinned", changed=True)
                else:
                    self._write_pin(server_id, tool.name, pin["def_hash"], "changed", changed=True)
            elif pin["status"] == "changed":
                state.status = "changed"
                state.reason = "its definition changed since it was first seen (possible rug-pull)"
            if scan:
                state.findings.extend(scan.findings)
                if description_action == "block":
                    state.status = "hidden"
                    state.reason = (
                        "its description contains instructions aimed at the model ("
                        + ", ".join(sorted({f.rule_id for f in scan.findings}))
                        + ")"
                    )
                    events.append((tool.name, "hidden"))
                    self._set_status(server_id, tool.name, "hidden")
            if state.status == "changed" and on_change == "block":
                state.status = "hidden"
                events.append((tool.name, "hidden"))
            self._descriptions[key] = tool.description
            self.state[key] = state
        return events

    def get(self, server_id: str, tool: str) -> ToolState:
        return self.state.get((server_id, tool), ToolState())

    def is_hidden(self, server_id: str, tool: str) -> bool:
        return self.get(server_id, tool).status == "hidden"

    def accept_change(self, server_id: str, tool: str, tool_def: types.Tool) -> None:
        """After a human approves a changed tool, its new definition becomes the pin."""
        self._write_pin(server_id, tool, definition_hash(tool_def), "pinned", changed=False)
        self.state[(server_id, tool)] = ToolState()

    def listing_findings(self) -> list[Finding]:
        """Fresh copies (unique ids) of every active definition finding, attached to each tools/list audit row."""
        out: list[Finding] = []
        for st in self.state.values():
            out.extend(f.model_copy(update={"id": new_id("f")}) for f in st.findings)
        return out

    # -- persistence ---------------------------------------------------------------

    def _write_pin(
        self, server_id: str, tool: str, h: str, status: Status, *, first: bool = False, changed: bool = False
    ) -> None:
        ts = now_iso()
        self.store.upsert_pin(
            server_id,
            tool,
            h,
            status,
            first_seen_at=ts if first else None,
            last_changed_at=ts if changed else None,
        )
        row = self._pins.get((server_id, tool), {"first_seen_at": ts, "last_changed_at": None})
        self._pins[(server_id, tool)] = {
            **row,
            "server_id": server_id,
            "tool": tool,
            "def_hash": h,
            "status": status,
        }

    def _set_status(self, server_id: str, tool: str, status: Status) -> None:
        pin = self._pins.get((server_id, tool))
        if pin is not None and pin["status"] != status:
            self._write_pin(server_id, tool, pin["def_hash"], status)
