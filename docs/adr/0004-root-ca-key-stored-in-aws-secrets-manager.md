# ADR-0004: Root CA key stored in AWS Secrets Manager

> Store the Root CA private key in AWS Secrets Manager and sync it into a Kubernetes Secret.

## Metadata

| Field | Value |
| :--- | :--- |
| **Document ID** | ADR-0004 |
| **Status** | `Accepted` |
| **Date** | N/A |
| **Deciders** | Wazuh maintainers |
| **Governs** | AWS Secrets Manager, ExternalSecrets, server, webhook |
| **Amends** | N/A |
| **Amended by** | N/A |
| **Supersedes** | N/A |
| **Superseded by** | N/A |

## Context

The Root CA private key is the crown jewel. It must be protected from disclosure and loss, and only mounted where it is needed.

## Decision

Store the Root CA key and certificate in AWS Secrets Manager and sync them into a Kubernetes Secret via ExternalSecrets. Mount the key read-only into the server; mount the certificate into the webhook for TLS verification of the Wazuh Manager API.

## Consequences

- Access to the key is governed by AWS IAM and the ExternalSecret.
- No documented rotation or compromise procedure yet (GAP-WCO-CA-01).
- The key is not part of the ledger/CRL/spool backups and must be protected separately.

## Rollback

Nothing to roll back.
