# ADR-0003: PostgreSQL as system of record for ledger / CRL / spool

> Use PostgreSQL as the system of record for the ledger, CRL cache, and webhook spool.

## Metadata

| Field | Value |
| :--- | :--- |
| **Document ID** | ADR-0003 |
| **Status** | `Accepted` |
| **Date** | N/A |
| **Deciders** | Wazuh maintainers |
| **Governs** | server ledger, webhook spool, model migrations |
| **Amends** | N/A |
| **Amended by** | N/A |
| **Supersedes** | N/A |
| **Superseded by** | N/A |

## Context

The server and webhook need durable, multi-replica-safe storage for the issuance ledger, the CRL, and the webhook spool. The initial implementation used on-disk storage: a CSV ledger for the server and JSON spool items for the webhook.

## Decision

Use PostgreSQL as the system of record when `DATABASE_URL` is set, replacing the on-disk CSV ledger and JSON spool. The ledger is stored as an append-only event log plus a materialized current state; the signed CRL is cached in a shared table with a change notification so replicas stay consistent; the webhook spool is stored in a shared table and claimed with row-level locking so multiple replicas can run safely. Keep the on-disk CSV / JSON fallback for local development and emergency use, with an `import-ledger` migration path.

Implementation: [server ledger](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/tree/main/crates/wazuh-cert-oauth2-server/src/shared/ledger), [webhook spool](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/tree/main/crates/wazuh-cert-oauth2-webhook/src/state/spool), [migrations](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/tree/main/crates/wazuh-cert-oauth2-model/migrations).

## Consequences

- Multi-replica consistency and durability when PostgreSQL is deployed.
- Production currently runs the on-disk fallback on EFS; PostgreSQL is not yet deployed (GAP-WCO-BKP-03).
- Adds a PostgreSQL dependency to the stack.

## Rollback

Nothing to roll back.
