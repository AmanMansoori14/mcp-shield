"""Wiring: config → meter → audit → upstream pool → security stages → pipeline → server."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import anyio
import anyio.to_thread
from mcp.server import Server

from mcp_shield.audit.logger import AuditLogger
from mcp_shield.audit.models import UpstreamSnapshot
from mcp_shield.audit.store import AuditStore
from mcp_shield.config import LoadedConfig, PolicyFile
from mcp_shield.metering.meter import Meter
from mcp_shield.metering.tokenizer import Tokenizer, make_tokenizer
from mcp_shield.pipeline.pipeline import Pipeline
from mcp_shield.proxy import router
from mcp_shield.proxy.audit_tools import AuditTools
from mcp_shield.proxy.server_face import ConnectionTracker, build_server, notify_list_changed
from mcp_shield.proxy.upstream_pool import Upstream, UpstreamPool
from mcp_shield.security.approval import Approver
from mcp_shield.security.pins import ToolGuard
from mcp_shield.security.policy import PolicyEngine, PolicyHolder
from mcp_shield.security.redactor import Redactor
from mcp_shield.security.scanner import Scanner
from mcp_shield.security.stages import (
    ArgScanStage,
    BudgetStage,
    GuardStage,
    PolicyStage,
    RedactStage,
    ResultScanStage,
    SchemaStage,
)

log = logging.getLogger(__name__)


class Shield:
    def __init__(
        self,
        upstreams: list[Upstream],
        *,
        db_path: Path | str,
        spool_path: Path | str,
        policy: PolicyFile | None = None,
        policy_path: Path | None = None,
        tokenizer: Tokenizer | None = None,
        image_tokens: int = 1500,
        offload_bytes: int = 32_768,
        input_price_per_million: float | None = None,
        queue_size: int = 10_000,
        spool_alert_mb: int = 100,
        store_payloads: bool = True,
        connection_kind: str = "stdio",
        audit_tools: bool = True,
        retention_days: int | None = 30,
        refresh_interval_s: float = 30.0,
        policy_reload_interval_s: float = 1.0,
        max_restarts: int = 3,
        restart_backoff_s: float = 1.0,
    ):
        self.store = AuditStore(db_path)
        self.policy_path = policy_path
        self.holder = PolicyHolder(policy or PolicyFile(), policy_path, on_swap=self._on_policy_swap)
        self.store.register_policy(
            self.holder.hash,
            str(policy_path) if policy_path else None,
            policy_path.read_text() if policy_path and policy_path.exists() else None,
        )
        self.audit = AuditLogger(
            self.store, spool_path, queue_size, spool_alert_bytes=spool_alert_mb * 1024 * 1024
        )
        self.meter = Meter(
            tokenizer or make_tokenizer(),
            image_tokens=image_tokens,
            offload_bytes=offload_bytes,
            input_price_per_million=input_price_per_million,
        )
        self.scanner = Scanner()
        self.redactor = Redactor()
        self.guard = ToolGuard(self.store, self.scanner, self.redactor)
        self.approver = Approver(ttl_s=self.holder.policy.approval.token_ttl_s)
        self.tracker = ConnectionTracker(connection_kind)
        self.pool = UpstreamPool(
            upstreams,
            on_change=self._on_upstream_change,
            max_restarts=max_restarts,
            backoff_s=restart_backoff_s,
        )
        policy_stage = PolicyStage(self.holder)
        arg_scan = ArgScanStage(self.scanner, self.holder)
        result_scan = ResultScanStage(self.scanner, self.holder)
        self.pipeline = Pipeline(
            self.meter,
            self.audit,
            policy_hash=lambda: self.holder.hash,
            store_payloads=store_payloads,
            redact=lambda v: self.redactor.redact_value(v)[0],
            pre_stages=[
                GuardStage(self.guard, self.holder),
                SchemaStage(),
                policy_stage,
                arg_scan,
            ],
            read_stages=[policy_stage, arg_scan],
            read_scan=result_scan.inspect,
            post_stages=[
                result_scan,
                RedactStage(self.redactor),
                BudgetStage(self.meter, self.holder),
            ],
        )
        self.retention_days = retention_days
        self.server: Server[Any] = build_server(
            self.pool,
            self.pipeline,
            self.tracker,
            guard=self.guard,
            approver=self.approver,
            audit_tools=AuditTools(self.store, self.audit.flush) if audit_tools else None,
            redactor=self.redactor,
        )
        self.refresh_interval_s = refresh_interval_s
        self.policy_reload_interval_s = policy_reload_interval_s
        self._stop = anyio.Event()

    @classmethod
    def from_config(cls, cfg: LoadedConfig, *, connection_kind: str = "stdio") -> Shield:
        pool = UpstreamPool.from_config(cfg.servers.servers)
        return cls(
            list(pool.upstreams.values()),
            db_path=cfg.resolve(cfg.shield.audit.db_path),
            spool_path=cfg.resolve(cfg.shield.audit.spool_path),
            policy=cfg.policy,
            policy_path=cfg.resolve(cfg.shield.policy) if cfg.shield.policy else None,
            tokenizer=make_tokenizer(
                cfg.shield.tokenizer.kind,
                cfg.shield.tokenizer.encoding,
                scale=cfg.shield.tokenizer.scale,
                model=cfg.shield.tokenizer.model,
            ),
            image_tokens=cfg.shield.tokenizer.image_tokens,
            offload_bytes=cfg.shield.tokenizer.offload_bytes,
            input_price_per_million=cfg.pricing.input_per_million if cfg.pricing else None,
            queue_size=cfg.shield.audit.queue_size,
            spool_alert_mb=cfg.shield.audit.spool_alert_mb,
            store_payloads=cfg.shield.audit.store_payloads,
            connection_kind=connection_kind,
            audit_tools=cfg.shield.audit_tools,
            retention_days=cfg.shield.audit.retention_days,
            refresh_interval_s=cfg.shield.refresh_interval_s,
            policy_reload_interval_s=cfg.shield.policy_reload_interval_s,
        )

    # -- lifecycle ---------------------------------------------------------------------

    @asynccontextmanager
    async def running(self) -> AsyncIterator[Shield]:
        """Start the audit logger, connect upstreams, screen their tools; tear down on exit."""
        self._stop = anyio.Event()
        async with anyio.create_task_group() as tg:
            await self.audit.start(tg)
            await self.pool.start(tg)
            await self.screen_tools()
            await self.snapshot_upstreams()
            tg.start_soon(self._every, self.policy_reload_interval_s, self._reload_policy)
            tg.start_soon(self._every, self.refresh_interval_s, self.refresh_upstreams)
            if self.retention_days:
                await self.prune()
                tg.start_soon(self._every, 3600.0, self.prune)
            try:
                yield self
            finally:
                self._stop.set()
                await self.pool.aclose()
                await self.audit.aclose()

    async def serve_stdio(self) -> None:
        from mcp.server.stdio import stdio_server

        async with self.running(), stdio_server() as (read, write):
            await self.server.run(read, write, self.server.create_initialization_options())

    async def _every(self, interval_s: float, fn: Any) -> None:
        while not self._stop.is_set():
            with anyio.move_on_after(interval_s):
                await self._stop.wait()
            if not self._stop.is_set():
                try:
                    await fn()
                except Exception:
                    log.exception("background task %s failed", getattr(fn, "__name__", fn))

    async def _reload_policy(self) -> None:
        self.holder.poll()  # TS-B2: an invalid file keeps the previous policy

    # -- upstream screening ---------------------------------------------------------------

    async def refresh_upstreams(self) -> None:
        """Re-list every live upstream and re-screen: catches rug-pulls on 2026-07-28 upstreams too."""
        for up in self.pool.upstreams.values():
            if up.client is not None:
                await self.pool.refresh(up.id)
        await self.screen_tools()
        await self.snapshot_upstreams()

    async def screen_tools(self) -> None:
        p = self.holder.policy
        for up in self.pool.upstreams.values():
            events = self.guard.screen(
                up.id,
                list(up.tools.values()),
                description_action=p.scanner.description_action,
                on_change=p.pinning.on_change,
            )
            for tool, event in events:
                log.warning("upstream %s tool %s: %s", up.id, tool, event)

    async def snapshot_upstreams(self) -> None:
        for up in self.pool.upstreams.values():
            visible = [t for t in up.tools.values() if not self.guard.is_hidden(up.id, t.name)]
            schema = await self.meter.definitions_tokens([router.namespaced_tool(up.id, t) for t in visible])
            snap = UpstreamSnapshot(
                server_id=up.id,
                status=up.status,  # type: ignore[arg-type]
                transport=up.transport,
                protocol_version=up.protocol_version,
                tool_count=len(visible),
                dropped_tools=up.dropped,
                schema_tokens=schema,
                last_error=up.last_error,
            )
            await anyio.to_thread.run_sync(self.store.write_upstream, snap)

    async def prune(self) -> int:
        """Retention: drop audit rows older than ``retention_days`` (tokens and findings cascade)."""
        if not self.retention_days:
            return 0
        cutoff = (datetime.now(UTC) - timedelta(days=self.retention_days)).isoformat(timespec="milliseconds")
        n = await anyio.to_thread.run_sync(self.store.delete_older_than, cutoff)
        if n:
            log.info("retention: pruned %d audit rows older than %d days", n, self.retention_days)
        return int(n)

    async def _on_upstream_change(self, server_id: str, kind: str) -> None:
        await self.screen_tools()
        await self.snapshot_upstreams()
        await notify_list_changed(self.tracker, kind)

    def _on_policy_swap(self, engine: PolicyEngine, source: str | None) -> None:
        self.store.register_policy(engine.hash, str(self.policy_path) if self.policy_path else None, source)
        self.approver.ttl_s = engine.policy.approval.token_ttl_s
