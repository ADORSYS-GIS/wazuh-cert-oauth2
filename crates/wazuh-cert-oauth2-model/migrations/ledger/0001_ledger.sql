-- PostgreSQL ledger schema (issue #292)
--
-- Two tables written in a single transaction:
--   * ledger_event  — append-only audit log
--   * ledger_entry  — materialized current state (system of record)

-- Append-only audit log
CREATE TABLE ledger_event (
    id               BIGSERIAL PRIMARY KEY,
    event_type       TEXT        NOT NULL,  -- 'ISSUED' | 'REVOKED' | 'STUB_REVOKED'
    subject          TEXT,
    serial_hex       TEXT        NOT NULL,  -- normalized UPPERCASE
    issued_at_unix   BIGINT,
    revoked_at_unix  BIGINT,
    reason           TEXT,
    issuer           TEXT,
    realm            TEXT,
    wazuh_agent_name TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_event_serial ON ledger_event (serial_hex);
CREATE INDEX idx_event_subject ON ledger_event (subject);

-- Current state (materialized)
CREATE TABLE ledger_entry (
    serial_hex       TEXT PRIMARY KEY,      -- normalized UPPERCASE
    subject          TEXT        NOT NULL,  -- '' for revoke-stubs
    issued_at_unix   BIGINT      NOT NULL,
    revoked          BOOLEAN     NOT NULL DEFAULT FALSE,
    revoked_at_unix  BIGINT,
    reason           TEXT,
    issuer           TEXT,
    realm            TEXT,
    wazuh_agent_name TEXT,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_entry_subject ON ledger_entry (subject);
