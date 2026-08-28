-- Webhook spool (issue #296)
--
-- Reliable-delivery queue for the webhook proxy. Replaces the on-disk JSON
-- spool directory so multiple webhook replicas can run safely via
-- SELECT ... FOR UPDATE SKIP LOCKED claim semantics.
--
-- `item_type` and `state` are Postgres ENUMs so invalid values are rejected
-- at the database level.

CREATE TYPE spool_item_type AS ENUM ('revoke', 'github_ticket', 'evict');
CREATE TYPE spool_state AS ENUM ('pending', 'in_progress', 'done', 'dead_letter');

CREATE TABLE spool_item (
    id                BIGSERIAL PRIMARY KEY,
    item_type         spool_item_type NOT NULL,
    payload           JSONB       NOT NULL,
    state             spool_state NOT NULL DEFAULT 'pending',
    triggered_at_unix BIGINT      NOT NULL,
    delete_after_unix BIGINT,               -- grace deadline (evict only)
    retry_count       INT         NOT NULL DEFAULT 0,
    last_error        TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_spool_due ON spool_item (state, delete_after_unix, triggered_at_unix)
    WHERE state = 'pending';
