"""TS-A5: SQLite store, async logger, JSONL spool and back-fill."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import anyio
import pytest

from mcp_shield.audit.logger import AuditLogger
from mcp_shield.audit.models import AuditRecord, ConnectionRecord, Finding, TokenRecord
from mcp_shield.audit.store import AuditStore

pytestmark = pytest.mark.anyio

CONN = ConnectionRecord(id="c_test", kind="in_process", client_name="pytest")


def record(i: int = 0, **kw: object) -> AuditRecord:
    base: dict[str, object] = dict(
        connection=CONN,
        method="tools/call",
        server_id="notes",
        tool="notes__echo",
        verdict="allow",
        latency_ms=1.5,
        shield_version="0.1.0",
        policy_hash="p_test",
        tokens=TokenRecord(
            request_tokens=i, response_tokens=2 * i, total_tokens=3 * i, tokenizer="char:len/4"
        ),
    )
    base.update(kw)
    return AuditRecord.model_validate(base)


def test_migrations_create_schema_and_are_idempotent(tmp_path: Path) -> None:
    store = AuditStore(tmp_path / "a.db")
    assert store.migrate() == 1
    tables = {r["name"] for r in store.query("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {
        "connections",
        "requests",
        "token_usage",
        "findings",
        "upstreams",
        "tool_pins",
        "policy_versions",
    } <= tables
    assert store.scalar("PRAGMA journal_mode") == "wal"


def test_write_is_atomic_and_idempotent(tmp_path: Path) -> None:
    store = AuditStore(tmp_path / "a.db")
    rec = record(5, findings=[Finding(stage="args", rule_id="args.schema_invalid", severity="low")])
    store.write(rec)
    store.write(rec)  # replay (e.g. back-fill) must not duplicate
    assert store.scalar("SELECT COUNT(*) FROM requests") == 1
    assert store.scalar("SELECT total_tokens FROM token_usage") == 15
    assert store.scalar("SELECT rule_id FROM findings") == "args.schema_invalid"


def test_invalid_verdict_is_rejected_by_schema(tmp_path: Path) -> None:
    store = AuditStore(tmp_path / "a.db")
    rec = record()
    object.__setattr__(rec, "verdict", "maybe")
    with pytest.raises(sqlite3.IntegrityError):
        store.write(rec)
    assert store.scalar("SELECT COUNT(*) FROM requests") == 0  # rolled back


def test_retention_cascades(tmp_path: Path) -> None:
    store = AuditStore(tmp_path / "a.db")
    store.write(
        record(1, created_at="2020-01-01T00:00:00.000+00:00", findings=[Finding(stage="x", rule_id="r")])
    )
    store.write(record(2))
    assert store.delete_older_than("2021-01-01") == 1
    assert store.scalar("SELECT COUNT(*) FROM token_usage") == 1
    assert store.scalar("SELECT COUNT(*) FROM findings") == 0


async def test_logger_writes_everything_submitted(tmp_path: Path) -> None:
    store = AuditStore(tmp_path / "a.db")
    logger = AuditLogger(store, tmp_path / "spool.jsonl")
    async with anyio.create_task_group() as tg:
        await logger.start(tg)
        for i in range(500):
            logger.submit(record(i))
        await logger.aclose()
    assert store.scalar("SELECT COUNT(*) FROM requests") == 500
    assert logger.spooled == 0


async def test_full_queue_spills_to_spool_then_backfills(tmp_path: Path) -> None:
    store = AuditStore(tmp_path / "a.db")
    logger = AuditLogger(store, tmp_path / "spool.jsonl", queue_size=1)
    async with anyio.create_task_group() as tg:
        await logger.start(tg)
        for i in range(50):  # submitted faster than the drain task can run
            logger.submit(record(i))
        await logger.aclose()
    assert logger.spooled > 0
    assert store.scalar("SELECT COUNT(*) FROM requests") == 50 - logger.spooled
    # Next start replays the spool: zero records lost (MP-C2).
    restarted = AuditLogger(store, tmp_path / "spool.jsonl")
    assert restarted.backfill() == logger.spooled
    assert store.scalar("SELECT COUNT(*) FROM requests") == 50
    assert not (tmp_path / "spool.jsonl").exists()


async def test_db_failure_spools_instead_of_dropping(tmp_path: Path) -> None:
    db = tmp_path / "a.db"
    AuditStore(db).close()
    readonly = AuditStore(db, read_only=True)  # every write fails
    logger = AuditLogger(readonly, tmp_path / "spool.jsonl")
    async with anyio.create_task_group() as tg:
        await logger.start(tg)
        for i in range(10):
            logger.submit(record(i))
        await logger.aclose()
    assert logger.spooled == 10 and logger.written == 0
    # Once the DB is writable again, the spool back-fills completely.
    assert AuditLogger(AuditStore(db), tmp_path / "spool.jsonl").backfill() == 10
