# ADR-0002: mTLS client certificates with CRL validation at the edge

> Issue per-subject mTLS client certificates and validate them against a live CRL at the edge.

## Metadata

| Field | Value |
| :--- | :--- |
| **Document ID** | ADR-0002 |
| **Status** | `Accepted` |
| **Date** | N/A |
| **Deciders** | Wazuh maintainers |
| **Governs** | nginx sidecar, server CRL, issued certificates |
| **Amends** | N/A |
| **Amended by** | N/A |
| **Supersedes** | N/A |
| **Superseded by** | N/A |

## Context

We needed a long-term credential that could be revoked quickly and validated at the point of enrollment, without relying on the manager alone.

## Decision

Issue per-subject mTLS client certificates (EKU `clientAuth`) signed by a Root CA, publish a Certificate Revocation List (CRL), and validate agent certificates against the live CRL via the nginx sidecar before proxying to the manager's `authd`.

## Consequences

- Revoked certificates are rejected at the edge even if the manager has not yet removed the agent.
- The Root CA private key becomes the single most sensitive asset [Access Control](https://adorsys.atlassian.net/wiki/x/AQA3t).
- Certificates are valid for 1 year (365 days); renewal relies on re-enrollment (GAP-WCO-CA-02).

## Rollback

Nothing to roll back.
