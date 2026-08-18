-- CRL cache (issue #294)
--
-- Single-row table holding the latest signed CRL (DER) plus its ETag and a
-- monotonically increasing generation counter. It lets multiple server
-- replicas serve a consistent CRL and avoid re-signing on every request.
-- The DER remains a derived, cacheable artifact; the ledger (ledger_entry
-- WHERE revoked = true) is the source of truth for revocations.

CREATE TABLE crl_cache (
    id          SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    der         BYTEA       NOT NULL,
    etag        TEXT        NOT NULL,
    generation  BIGINT      NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
