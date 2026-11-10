# ADR-0006: Auto-rotate / single-certificate policy

> Enforce one live certificate per subject; re-enrollment revokes the previous certificate.

## Metadata

| Field | Value |
| :--- | :--- |
| **Document ID** | ADR-0006 |
| **Status** | `Accepted` |
| **Date** | N/A |
| **Deciders** | Wazuh maintainers |
| **Governs** | server (re-enrollment), webhook (eviction) |
| **Amends** | N/A |
| **Amended by** | N/A |
| **Supersedes** | N/A |
| **Superseded by** | N/A |

## Context

Without a policy, a subject could hold multiple live certificates, and stale agents could remain enrolled after re-enrollment.

## Decision

Enforce one live certificate per subject. When an agent re-enrolls with `overwrite`, the server revokes any active certificate for the same subject, rebuilds the CRL, and notifies the webhook to evict the stale agent immediately (no grace period). Keycloak entities (users or service accounts) holding the `wazuh_admin` role are **exempt** from the single-certificate policy, they may hold more than one live certificate.

## Consequences

- One live certificate per subject.
- Re-enrollment doubles as the renewal path (1-year validity).
- Auto-rotate evictions skip the grace period, so the old agent is removed immediately.

## Rollback

Nothing to roll back.
