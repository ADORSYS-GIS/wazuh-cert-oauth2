-- PostgreSQL ledger schema rollback (issue #292)
--
-- Drops the materialized state and the append-only audit log. Dropping the
-- tables also drops their indexes.

DROP TABLE IF EXISTS ledger_entry;
DROP TABLE IF EXISTS ledger_event;
