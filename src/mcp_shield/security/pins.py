"""Tool pinning and definition screening (TS-B9, IP-A16, MP-B3).

Each upstream tool definition (name, description, schemas, annotations) is hashed the
first time Shield sees it. A later listing with a different hash is a rug-pull
candidate: the tool is re-scanned and flagged ``changed``; ``pinning.on_change``
decides whether it is only warned about, blocked, or needs approval on next use.

Descriptions are scanned on every listing; with ``scanner.description_action: block``
a poisoned tool is hidden from clients and any call to it is refused.

The pin row also keeps the latest description, the description before the last change
(both redacted) and the reason a tool is hidden or flagged, for the Upstreams page (gap #24).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Literal

from mcp import types

from mcp_shield.audit.models import Finding, new_id, now_iso
from mcp_shield.audit.store import AuditStore
from mcp_shield.security.redactor import Redactor
from mcp_shield.security.scanner import Scanner

Status = Literal["pinned", "changed", "hidden"]
CHANGED_REASON = "its definition changed since it was first seen (possible rug-pull)"


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

    def __init__(self, store: AuditStore, scanner: Scanner, redactor: Redactor | None = None):
        self.store = store
        self.scanner = scanner
        self.redactor = redactor or Redactor()
        self.state: dict[tuple[str, str], ToolState] = {}
        self._pins: dict[tuple[str, str], dict[str, Any]] = {
            (r["server_id"], r["tool"]): dict(r) for r in store.query("SELECT * FROM tool_pins")
        }

    def _clean(self, description: str | None) -> str:
        return self.redactor.redact_text(description or "")[0]

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
            desc = self._clean(tool.description)
            scan = self.scanner.scan_tool_definition(tool.name, tool.description, tool.input_schema)
            state = ToolState()
            pin = self._pins.get(key)
            if pin is None:
                self._write_pin(server_id, tool.name, h, "pinned", first=True, description=desc)
            elif pin["def_hash"] != h:
                # The description before this change: the stored one, unless this listing was
                # already recorded (an unaccepted change is seen again on every re-list).
                stored = pin.get("description")
                prev = pin.get("previous_description") if stored == desc else stored
                state.status = "changed"
                state.previous_description = prev
                state.reason = CHANGED_REASON
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
                    self._write_pin(
                        server_id,
                        tool.name,
                        h,
                        "pinned",
                        changed=stored != desc,
                        description=desc,
                        previous_description=prev,
                    )
                else:
                    reason = CHANGED_REASON + (
                        "; hidden until accepted (pinning.on_change: block)" if on_change == "block" else ""
                    )
                    self._write_pin(
                        server_id,
                        tool.name,
                        pin["def_hash"],
                        "changed",
                        changed=True,
                        reason=reason,
                        description=desc,
                        previous_description=prev,
                    )
            else:
                if pin["status"] == "changed":
                    state.status = "changed"
                    state.reason = CHANGED_REASON
                    state.previous_description = pin.get("previous_description")
                if pin.get("description") is None:  # pinned before descriptions were stored
                    self._write_pin(
                        server_id, tool.name, h, pin["status"], description=desc, reason=pin.get("reason")
                    )
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
                    self._set_status(server_id, tool.name, "hidden", state.reason)
            if state.status == "changed" and on_change == "block":
                state.status = "hidden"
                events.append((tool.name, "hidden"))
            self.state[key] = state
        return events

    def get(self, server_id: str, tool: str) -> ToolState:
        return self.state.get((server_id, tool), ToolState())

    def is_hidden(self, server_id: str, tool: str) -> bool:
        return self.get(server_id, tool).status == "hidden"

    def accept_change(self, server_id: str, tool: str, tool_def: types.Tool) -> None:
        """After a human approves a changed tool, its new definition becomes the pin."""
        self._write_pin(
            server_id,
            tool,
            definition_hash(tool_def),
            "pinned",
            description=self._clean(tool_def.description),
        )
        self.state[(server_id, tool)] = ToolState()

    def listing_findings(self) -> list[Finding]:
        """Fresh copies (unique ids) of every active definition finding, attached to each tools/list audit row."""
        out: list[Finding] = []
        for st in self.state.values():
            out.extend(f.model_copy(update={"id": new_id("f")}) for f in st.findings)
        return out

    # -- persistence ---------------------------------------------------------------

    def _write_pin(
        self,
        server_id: str,
        tool: str,
        h: str,
        status: Status,
        *,
        first: bool = False,
        changed: bool = False,
        description: str | None = None,
        previous_description: str | None = None,
        reason: str | None = None,
    ) -> None:
        ts = now_iso()
        self.store.upsert_pin(
            server_id,
            tool,
            h,
            status,
            first_seen_at=ts if first else None,
            last_changed_at=ts if changed else None,
            description=description,
            previous_description=previous_description,
            reason=reason,
        )
        row = self._pins.get((server_id, tool), {"first_seen_at": ts, "last_changed_at": None})
        self._pins[(server_id, tool)] = {  # mirror the upsert's COALESCE rules
            **row,
            "server_id": server_id,
            "tool": tool,
            "def_hash": h,
            "status": status,
            "last_changed_at": ts if changed else row.get("last_changed_at"),
            "description": description if description is not None else row.get("description"),
            "previous_description": previous_description
            if previous_description is not None
            else row.get("previous_description"),
            "reason": reason,
        }

    def _set_status(self, server_id: str, tool: str, status: Status, reason: str | None) -> None:
        pin = self._pins.get((server_id, tool))
        if pin is not None and (pin["status"] != status or pin.get("reason") != reason):
            self._write_pin(server_id, tool, pin["def_hash"], status, reason=reason)
