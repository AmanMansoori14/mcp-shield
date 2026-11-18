"""Wiring: config → tokenizer/meter → audit store/logger → upstream pool → pipeline → server."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import anyio
import anyio.to_thread
from mcp.server import Server

from mcp_shield.audit.logger import AuditLogger
from mcp_shield.audit.models import ConnectionKind, UpstreamSnapshot
from mcp_shield.audit.store import AuditStore
from mcp_shield.config import LoadedConfig
from mcp_shield.metering.meter import Meter
from mcp_shield.metering.tokenizer import Tokenizer, make_tokenizer
from mcp_shield.pipeline.pipeline import Pipeline
from mcp_shield.proxy import router
from mcp_shield.proxy.server_face import ConnectionTracker, build_server, notify_list_changed
from mcp_shield.proxy.upstream_pool import Upstream, UpstreamPool

log = logging.getLogger(__name__)


class Shield:
    def __init__(
        self,
        upstreams: list[Upstream],
        *,
        db_path: Path | str,
        spool_path: Path | str,
        policy_hash: str | None = None,
        policy_source: tuple[str | None, str | None] = (None, None),
        tokenizer: Tokenizer | None = None,
        image_tokens: int = 1500,
        offload_bytes: int = 32_768,
        input_price_per_million: float | None = None,
        queue_size: int = 10_000,
        store_payloads: bool = False,
        connection_kind: ConnectionKind = "stdio",
        fail_open: bool = False,
    ):
        self.store = AuditStore(db_path)
        if policy_hash:
            self.store.register_policy(policy_hash, *policy_source)
        self.audit = AuditLogger(self.store, spool_path, queue_size)
        self.meter = Meter(
            tokenizer or make_tokenizer(),
            image_tokens=image_tokens,
            offload_bytes=offload_bytes,
            input_price_per_million=input_price_per_million,
        )
        self.tracker = ConnectionTracker(connection_kind)
        self.pool = UpstreamPool(upstreams, on_change=self._on_upstream_change)
        self.pipeline = Pipeline(
            self.meter,
            self.audit,
            policy_hash=policy_hash,
            store_payloads=store_payloads,
            fail_open=fail_open,
        )
        self.server: Server[Any] = build_server(self.pool, self.pipeline, self.tracker)

    @classmethod
    def from_config(cls, cfg: LoadedConfig, *, connection_kind: ConnectionKind = "stdio") -> Shield:
        pool = UpstreamPool.from_config(cfg.servers.servers)
        policy_path = str(cfg.resolve(cfg.shield.policy)) if cfg.shield.policy else None
        return cls(
            list(pool.upstreams.values()),
            db_path=cfg.resolve(cfg.shield.audit.db_path),
            spool_path=cfg.resolve(cfg.shield.audit.spool_path),
            policy_hash=cfg.policy_hash,
            policy_source=(policy_path, cfg.policy_source),
            tokenizer=make_tokenizer(cfg.shield.tokenizer.kind, cfg.shield.tokenizer.encoding),
            image_tokens=cfg.shield.tokenizer.image_tokens,
            offload_bytes=cfg.shield.tokenizer.offload_bytes,
            input_price_per_million=cfg.pricing.input_per_million if cfg.pricing else None,
            queue_size=cfg.shield.audit.queue_size,
            connection_kind=connection_kind,
            fail_open=cfg.policy.defaults.fail_open,
        )

    @asynccontextmanager
    async def running(self) -> AsyncIterator[Shield]:
        """Start the audit logger and connect upstreams; tear both down on exit."""
        async with anyio.create_task_group() as tg:
            await self.audit.start(tg)
            await self.pool.start(tg)
            await self.snapshot_upstreams()
            try:
                yield self
            finally:
                await self.pool.aclose()
                await self.audit.aclose()

    async def serve_stdio(self) -> None:
        from mcp.server.stdio import stdio_server

        async with self.running(), stdio_server() as (read, write):
            await self.server.run(read, write, self.server.create_initialization_options())

    async def snapshot_upstreams(self) -> None:
        for up in self.pool.upstreams.values():
            schema = await self.meter.definitions_tokens(
                [router.namespaced_tool(up.id, t) for t in up.tools.values()]
            )
            snap = UpstreamSnapshot(
                server_id=up.id,
                status=up.status,  # type: ignore[arg-type]
                transport=up.transport,
                protocol_version=up.protocol_version,
                tool_count=len(up.tools),
                dropped_tools=up.dropped,
                schema_tokens=schema,
                last_error=up.last_error,
            )
            await anyio.to_thread.run_sync(self.store.write_upstream, snap)

    async def _on_upstream_change(self, server_id: str, kind: str) -> None:
        await self.snapshot_upstreams()
        await notify_list_changed(self.tracker, kind)
