# ADR-0005: Webhook spooling for at-least-once delivery

> Persist outbound revocations/evictions to a spool and retry with backoff for at-least-once delivery.

## Metadata

| Field | Value |
| :--- | :--- |
| **Document ID** | ADR-0005 |
| **Status** | `Accepted` |
| **Date** | N/A |
| **Deciders** | Wazuh maintainers |
| **Governs** | webhook spool (PostgreSQL spool_item or on-disk JSON) |
| **Amends** | N/A |
| **Amended by** | N/A |
| **Supersedes** | N/A |
| **Superseded by** | N/A |

## Context

Revocations and evictions are security-critical and cannot be fire-and-forget. If the server or Wazuh Manager is temporarily unavailable, the action must still be delivered.

## Decision

The webhook persists outbound requests (revocations, evictions, GitHub tickets) to a spool (PostgreSQL `spool_item` or on-disk JSON) and retries them with exponential backoff. Eviction items older than a TTL are moved to a dead-letter directory for operator inspection or replay.

## Consequences

- At-least-once delivery with bounded retry.
- A certificate that must be revoked is revoked as soon as the system can reach the server.
- Requires durable storage for the spool (EFS today, PostgreSQL when deployed).

## Rollback

Nothing to roll back.
