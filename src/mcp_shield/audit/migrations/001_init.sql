-- MCP Shield audit schema v1 (IP schema direction, PRD v1.1)

CREATE TABLE connections (
    id               TEXT PRIMARY KEY,
    kind             TEXT NOT NULL CHECK (kind IN ('stdio', 'legacy_session', 'grouped', 'in_process')),
    client_name      TEXT,
    client_version   TEXT,
    protocol_version TEXT,
    capabilities     TEXT,                      -- JSON
    started_at       TEXT NOT NULL,
    last_seen_at     TEXT NOT NULL
);

CREATE TABLE policy_versions (
    hash         TEXT PRIMARY KEY,
    loaded_at    TEXT NOT NULL,
    source_path  TEXT,
    yaml_source  TEXT
);

CREATE TABLE requests (
    id                TEXT PRIMARY KEY,
    connection_id     TEXT NOT NULL REFERENCES connections(id),
    logical_call_id   TEXT NOT NULL,
    leg               INTEGER NOT NULL DEFAULT 1 CHECK (leg IN (1, 2)),
    protocol_version  TEXT,
    jsonrpc_id        TEXT,
    direction         TEXT NOT NULL DEFAULT 'client_to_server'
                          CHECK (direction IN ('client_to_server', 'server_to_client', 'upstream_to_shield')),
    method            TEXT NOT NULL,
    server_id         TEXT,
    tool              TEXT,
    verdict           TEXT NOT NULL CHECK (verdict IN
                          ('allow', 'warn', 'block', 'approval_pending', 'approved', 'denied', 'expired', 'error')),
    error_code        INTEGER,
    error_message     TEXT,
    latency_ms        REAL NOT NULL,
    upstream_ms       REAL,
    approval_ms       REAL,
    stage_ms          TEXT,                     -- JSON {stage: ms}
    params_redacted   TEXT,
    result_redacted   TEXT,
    payload_truncated INTEGER NOT NULL DEFAULT 0,
    policy_hash       TEXT REFERENCES policy_versions(hash),
    shield_version    TEXT NOT NULL,
    created_at        TEXT NOT NULL
);

CREATE TABLE token_usage (
    request_id       TEXT PRIMARY KEY REFERENCES requests(id) ON DELETE CASCADE,
    request_tokens   INTEGER NOT NULL DEFAULT 0 CHECK (request_tokens >= 0),
    response_tokens  INTEGER NOT NULL DEFAULT 0 CHECK (response_tokens >= 0),
    schema_tokens    INTEGER NOT NULL DEFAULT 0 CHECK (schema_tokens >= 0),
    total_tokens     INTEGER NOT NULL DEFAULT 0 CHECK (total_tokens >= 0),
    est_cost_usd     REAL,
    tokenizer        TEXT NOT NULL,
    estimated        INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE findings (
    id               TEXT PRIMARY KEY,
    request_id       TEXT NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
    stage            TEXT NOT NULL,
    rule_id          TEXT NOT NULL,
    severity         TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    target           TEXT,
    snippet_hash     TEXT,
    excerpt_redacted TEXT
);

CREATE TABLE upstreams (
    server_id      TEXT PRIMARY KEY,
    status         TEXT NOT NULL CHECK (status IN ('up', 'down', 'degraded')),
    transport      TEXT NOT NULL,
    protocol_version TEXT,
    tool_count     INTEGER NOT NULL DEFAULT 0,
    dropped_tools  TEXT,                        -- JSON [{name, reason}]
    schema_tokens  INTEGER NOT NULL DEFAULT 0,
    last_error     TEXT,
    checked_at     TEXT NOT NULL
);

CREATE TABLE tool_pins (
    server_id        TEXT NOT NULL,
    tool             TEXT NOT NULL,
    def_hash         TEXT NOT NULL,
    first_seen_at    TEXT NOT NULL,
    last_changed_at  TEXT,
    status           TEXT NOT NULL DEFAULT 'pinned' CHECK (status IN ('pinned', 'changed', 'hidden')),
    PRIMARY KEY (server_id, tool)
);

CREATE INDEX idx_requests_created      ON requests(created_at);
CREATE INDEX idx_requests_connection   ON requests(connection_id);
CREATE INDEX idx_requests_logical      ON requests(logical_call_id);
CREATE INDEX idx_requests_server_tool  ON requests(server_id, tool, created_at);
CREATE INDEX idx_requests_verdict      ON requests(verdict, created_at);
CREATE INDEX idx_findings_request      ON findings(request_id);
CREATE INDEX idx_findings_rule         ON findings(rule_id);
