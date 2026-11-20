"""SQLite audit store (TS-A5).

WAL mode, plain-SQL migrations applied on open, one transaction per audit record.
All methods are synchronous and thread-safe; the async ``AuditLogger`` calls them
from a worker thread so the request path never waits on disk.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from importlib import resources
from pathlib import Path
from typing import Any

from mcp_shield.audit.models import AuditRecord, ConnectionRecord, UpstreamSnapshot, now_iso


class AuditStore:
    def __init__(self, path: Path | str, *, read_only: bool = False):
        self.path = str(path)
        if read_only:
            uri = f"file:{Path(self.path).resolve()}?mode=ro"
            self._db = sqlite3.connect(uri, uri=True, check_same_thread=False)
        else:
            self._db = sqlite3.connect(self.path, check_same_thread=False, timeout=5.0)
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        if not read_only:
            self.migrate()

    # -- schema -----------------------------------------------------------

    def migrate(self) -> int:
        with self._lock:
            self._db.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY)")
            current = self._db.execute("SELECT COALESCE(MAX(version), 0) FROM schema_version").fetchone()[0]
            files = sorted(
                (
                    f
                    for f in resources.files("mcp_shield.audit.migrations").iterdir()
                    if f.name.endswith(".sql")
                ),
                key=lambda f: f.name,
            )
            for f in files:
                version = int(f.name.split("_", 1)[0])
                if version > current:
                    self._db.executescript(f.read_text())
                    self._db.execute("INSERT INTO schema_version (version) VALUES (?)", (version,))
                    self._db.commit()
                    current = version
            return int(current)

    # -- writes -----------------------------------------------------------

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                yield self._db
                self._db.commit()
            except BaseException:
                self._db.rollback()
                raise

    def register_policy(self, policy_hash: str, source_path: str | None, yaml_source: str | None) -> None:
        with self._tx() as db:
            db.execute(
                "INSERT OR IGNORE INTO policy_versions (hash, loaded_at, source_path, yaml_source) VALUES (?,?,?,?)",
                (policy_hash, now_iso(), source_path, yaml_source),
            )

    def write(self, rec: AuditRecord) -> None:
        """Persist one record (connection upsert + request + tokens + findings) atomically."""
        with self._tx() as db:
            self._upsert_connection(db, rec.connection)
            if rec.policy_hash:
                db.execute(
                    "INSERT OR IGNORE INTO policy_versions (hash, loaded_at) VALUES (?, ?)",
                    (rec.policy_hash, now_iso()),
                )
            db.execute(
                """INSERT OR IGNORE INTO requests (
                    id, connection_id, logical_call_id, leg, protocol_version, jsonrpc_id, direction, method,
                    server_id, tool, verdict, error_code, error_message, latency_ms, upstream_ms, approval_ms,
                    stage_ms, params_redacted, result_redacted, payload_truncated, policy_hash, shield_version,
                    created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    rec.id,
                    rec.connection.id,
                    rec.logical_call_id,
                    rec.leg,
                    rec.protocol_version,
                    rec.jsonrpc_id,
                    rec.direction,
                    rec.method,
                    rec.server_id,
                    rec.tool,
                    rec.verdict,
                    rec.error_code,
                    rec.error_message,
                    rec.latency_ms,
                    rec.upstream_ms,
                    rec.approval_ms,
                    json.dumps(rec.stage_ms),
                    rec.params_redacted,
                    rec.result_redacted,
                    int(rec.payload_truncated),
                    rec.policy_hash,
                    rec.shield_version,
                    rec.created_at,
                ),
            )
            t = rec.tokens
            db.execute(
                """INSERT OR IGNORE INTO token_usage (request_id, request_tokens, response_tokens, schema_tokens,
                    total_tokens, est_cost_usd, tokenizer, estimated) VALUES (?,?,?,?,?,?,?,?)""",
                (
                    rec.id,
                    t.request_tokens,
                    t.response_tokens,
                    t.schema_tokens,
                    t.total_tokens,
                    t.est_cost_usd,
                    t.tokenizer,
                    int(t.estimated),
                ),
            )
            db.executemany(
                """INSERT OR IGNORE INTO findings (id, request_id, stage, rule_id, severity, target, snippet_hash,
                    excerpt_redacted) VALUES (?,?,?,?,?,?,?,?)""",
                [
                    (
                        f.id,
                        rec.id,
                        f.stage,
                        f.rule_id,
                        f.severity,
                        f.target,
                        f.snippet_hash,
                        f.excerpt_redacted,
                    )
                    for f in rec.findings
                ],
            )

    def write_upstream(self, snap: UpstreamSnapshot) -> None:
        with self._tx() as db:
            db.execute(
                """INSERT INTO upstreams (server_id, status, transport, protocol_version, tool_count,
                    dropped_tools, schema_tokens, last_error, checked_at) VALUES (?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(server_id) DO UPDATE SET status=excluded.status, transport=excluded.transport,
                    protocol_version=excluded.protocol_version, tool_count=excluded.tool_count,
                    dropped_tools=excluded.dropped_tools, schema_tokens=excluded.schema_tokens,
                    last_error=excluded.last_error, checked_at=excluded.checked_at""",
                (
                    snap.server_id,
                    snap.status,
                    snap.transport,
                    snap.protocol_version,
                    snap.tool_count,
                    json.dumps(snap.dropped_tools),
                    snap.schema_tokens,
                    snap.last_error,
                    snap.checked_at,
                ),
            )

    @staticmethod
    def _upsert_connection(db: sqlite3.Connection, c: ConnectionRecord) -> None:
        db.execute(
            """INSERT INTO connections (id, kind, client_name, client_version, protocol_version, capabilities,
                started_at, last_seen_at) VALUES (?,?,?,?,?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET last_seen_at=excluded.last_seen_at,
                protocol_version=COALESCE(excluded.protocol_version, connections.protocol_version),
                client_name=COALESCE(excluded.client_name, connections.client_name),
                client_version=COALESCE(excluded.client_version, connections.client_version)""",
            (
                c.id,
                c.kind,
                c.client_name,
                c.client_version,
                c.protocol_version,
                json.dumps(c.capabilities) if c.capabilities is not None else None,
                c.started_at,
                c.last_seen_at,
            ),
        )

    def upsert_pin(
        self,
        server_id: str,
        tool: str,
        def_hash: str,
        status: str,
        *,
        first_seen_at: str | None = None,
        last_changed_at: str | None = None,
        description: str | None = None,
        previous_description: str | None = None,
        reason: str | None = None,
    ) -> None:
        """Insert or update a pin. ``description`` and ``previous_description`` keep their stored value
        when passed as None; ``reason`` is always replaced (None clears it)."""
        with self._tx() as db:
            db.execute(
                """INSERT INTO tool_pins (server_id, tool, def_hash, first_seen_at, last_changed_at, status,
                                          description, previous_description, reason)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(server_id, tool) DO UPDATE SET def_hash=excluded.def_hash, status=excluded.status,
                    last_changed_at=COALESCE(excluded.last_changed_at, tool_pins.last_changed_at),
                    description=COALESCE(excluded.description, tool_pins.description),
                    previous_description=COALESCE(excluded.previous_description, tool_pins.previous_description),
                    reason=excluded.reason""",
                (
                    server_id,
                    tool,
                    def_hash,
                    first_seen_at or now_iso(),
                    last_changed_at,
                    status,
                    description,
                    previous_description,
                    reason,
                ),
            )

    def delete_older_than(self, cutoff_iso: str) -> int:
        """Retention: drop requests (and, by cascade, their tokens and findings) created before ``cutoff_iso``."""
        with self._tx() as db:
            return db.execute("DELETE FROM requests WHERE created_at < ?", (cutoff_iso,)).rowcount

    # -- reads (dashboard/tests) -------------------------------------------

    def query(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self._db.execute(sql, params).fetchall()]

    def scalar(self, sql: str, params: tuple[Any, ...] = ()) -> Any:
        with self._lock:
            row = self._db.execute(sql, params).fetchone()
            return row[0] if row else None

    def close(self) -> None:
        with self._lock:
            self._db.close()
