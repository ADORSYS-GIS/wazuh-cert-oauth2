-- Webhook spool rollback (issue #296)

DROP TABLE IF EXISTS spool_item;
DROP TYPE IF EXISTS spool_item_type;
DROP TYPE IF EXISTS spool_state;
