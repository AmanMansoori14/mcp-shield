"""Async audit logger (TS-A5, IP-A10).

``submit()`` never blocks the request path: records go into a bounded in-memory
buffer drained by one background task that writes on a worker thread. If the
buffer is full, or a write fails (DB locked, read-only, disk full), the record is
appended to a JSONL spool instead. The spool is replayed into the DB on the next
start, so no record is lost (MP-C2).
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path

import anyio
import anyio.to_thread
from anyio.abc import TaskGroup
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream

from mcp_shield.audit.models import AuditRecord
from mcp_shield.audit.store import AuditStore

log = logging.getLogger(__name__)


class AuditLogger:
    def __init__(self, store: AuditStore, spool_path: Path | str, queue_size: int = 10_000):
        self.store = store
        self.spool_path = Path(spool_path)
        self.queue_size = queue_size
        self._send: MemoryObjectSendStream[AuditRecord] | None = None
        self._recv: MemoryObjectReceiveStream[AuditRecord] | None = None
        self._spool_lock = threading.Lock()
        self.written = 0
        self.spooled = 0

    # -- lifecycle ---------------------------------------------------------

    async def start(self, tg: TaskGroup) -> None:
        await anyio.to_thread.run_sync(self.backfill)
        self._send, self._recv = anyio.create_memory_object_stream[AuditRecord](self.queue_size)
        tg.start_soon(self._drain, self._recv)

    async def aclose(self) -> None:
        """Stop accepting records; the drain task finishes what's buffered, then exits."""
        if self._send is not None:
            await self._send.aclose()
            self._send = None

    # -- request path ------------------------------------------------------

    def submit(self, rec: AuditRecord) -> None:
        if self._send is None:
            self._spool(rec)
            return
        try:
            self._send.send_nowait(rec)
        except (anyio.WouldBlock, anyio.ClosedResourceError, anyio.BrokenResourceError):
            self._spool(rec)

    # -- background --------------------------------------------------------

    async def _drain(self, recv: MemoryObjectReceiveStream[AuditRecord]) -> None:
        async with recv:
            async for rec in recv:
                try:
                    await anyio.to_thread.run_sync(self.store.write, rec)
                    self.written += 1
                except Exception as e:
                    log.warning("audit write failed (%s); spooling %s", e, rec.id)
                    self._spool(rec)

    def _spool(self, rec: AuditRecord) -> None:
        line = rec.model_dump_json() + "\n"
        with self._spool_lock, self.spool_path.open("a", encoding="utf-8") as f:
            f.write(line)
        self.spooled += 1

    def backfill(self) -> int:
        """Replay the spool into the DB. Inserts are idempotent (INSERT OR IGNORE on record ids)."""
        if not self.spool_path.exists():
            return 0
        with self._spool_lock:
            lines = self.spool_path.read_text(encoding="utf-8").splitlines()
            replayed, remaining = 0, []
            for line in lines:
                if not line.strip():
                    continue
                try:
                    self.store.write(AuditRecord.model_validate_json(line))
                    replayed += 1
                except Exception as e:
                    log.warning("backfill failed for one record (%s); keeping it in the spool", e)
                    remaining.append(line)
            if remaining:
                self.spool_path.write_text("\n".join(remaining) + "\n", encoding="utf-8")
            else:
                self.spool_path.unlink()
        if replayed:
            log.info("backfilled %d audit records from %s", replayed, self.spool_path)
        return replayed
