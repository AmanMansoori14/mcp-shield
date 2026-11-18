from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest
from mcp import Client

from mcp_shield.app import Shield
from mcp_shield.metering.tokenizer import CharHeuristicTokenizer
from mcp_shield.proxy.upstream_pool import Upstream

# Every integration test runs against both protocol revisions (MP-B1): a modern
# 2026-07-28 client and a legacy 2025-11-25 client.
MODES = ["auto", "legacy"]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(params=MODES)
def mode(request: pytest.FixtureRequest) -> str:
    return str(request.param)


ShieldFactory = Callable[..., Any]


@pytest.fixture
def make_shield(tmp_path: Path) -> ShieldFactory:
    @asynccontextmanager
    async def factory(
        upstreams: dict[str, Any],
        *,
        mode: str = "auto",
        timeout_s: float = 10.0,
        **kwargs: Any,
    ) -> AsyncIterator[tuple[Shield, Client]]:
        shield = Shield(
            [
                Upstream(id=k, transport="in_process", target=v, timeout_s=timeout_s)
                for k, v in upstreams.items()
            ],
            db_path=tmp_path / "audit.db",
            spool_path=tmp_path / "audit.spool.jsonl",
            tokenizer=kwargs.pop("tokenizer", CharHeuristicTokenizer()),
            connection_kind="in_process",
            **kwargs,
        )
        async with shield.running(), Client(shield.server, mode=mode) as client:  # type: ignore[arg-type]
            yield shield, client

    return factory
