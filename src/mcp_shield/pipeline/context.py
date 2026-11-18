"""Per-request state carried through the pipeline (IP pipeline step 1)."""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

from mcp_shield.audit.models import ConnectionRecord, Finding, new_id, worst


@dataclass
class RequestContext:
    connection: ConnectionRecord
    method: str
    protocol_version: str | None = None
    jsonrpc_id: str | None = None
    server_id: str | None = None
    tool: str | None = None
    params: dict[str, Any] | None = None
    request_id: str = field(default_factory=lambda: new_id("r"))
    logical_call_id: str = field(default_factory=lambda: new_id("lc"))
    leg: int = 1
    verdict: str = "allow"
    reason: str | None = None
    error_code: int | None = None
    findings: list[Finding] = field(default_factory=list)
    stage_ms: dict[str, float] = field(default_factory=dict)
    upstream_ms: float | None = None
    t0: float = field(default_factory=time.perf_counter)

    @contextmanager
    def stage(self, name: str) -> Iterator[None]:
        """Time a pipeline stage; the duration lands in ``stage_ms`` even if the stage raises."""
        start = time.perf_counter()
        try:
            yield
        finally:
            elapsed = (time.perf_counter() - start) * 1000
            self.stage_ms[name] = round(self.stage_ms.get(name, 0.0) + elapsed, 3)

    def escalate(self, verdict: str, reason: str | None = None) -> None:
        """Combine verdicts worst-of (IP pipeline step 11); the first reason for the winning verdict sticks."""
        new = worst(self.verdict, verdict)
        if new != self.verdict or (reason and not self.reason):
            self.reason = reason if new == verdict else self.reason
        self.verdict = new

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    @property
    def elapsed_ms(self) -> float:
        return round((time.perf_counter() - self.t0) * 1000, 3)
