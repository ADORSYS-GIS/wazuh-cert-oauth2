# Architecture Decision Records

Every architectural decision is recorded here as a numbered ADR: one file per
decision. The canonical writing guidance is the central ADR guide:
<https://github.com/ADORSYS-GIS/wazuh/blob/main/docs/adr/GUIDE.md>
(read it before writing an ADR). The canonical template is:
<https://github.com/ADORSYS-GIS/wazuh/blob/main/docs/adr/template.md>.

## Index

| ID                                      | Title                         | Status     | Date       | Relations | Formerly |
| :-------------------------------------- | :---------------------------- | :--------- | :--------- | :-------- | :------- |
| [ADR-0001](0001-oidc-oauth2-for-agent-authentication.md) | OIDC / OAuth2 for agent authentication | `Accepted` | N/A | N/A | N/A |
| [ADR-0002](0002-mtls-client-certificates-with-crl-validation-at-the-edge.md) | mTLS client certificates with CRL validation at the edge | `Accepted` | N/A | N/A | N/A |
| [ADR-0003](0003-postgresql-as-system-of-record-for-ledger-crl-spool.md) | PostgreSQL as system of record for ledger / CRL / spool | `Accepted` | N/A | N/A | N/A |
| [ADR-0004](0004-root-ca-key-stored-in-aws-secrets-manager.md) | Root CA key stored in AWS Secrets Manager | `Accepted` | N/A | N/A | N/A |
| [ADR-0005](0005-webhook-spooling-for-at-least-once-delivery.md) | Webhook spooling for at-least-once delivery | `Accepted` | N/A | N/A | N/A |
| [ADR-0006](0006-auto-rotate-single-certificate-policy.md) | Auto-rotate / single-certificate policy | `Accepted` | N/A | N/A | N/A |
| [ADR-0007](0007-distroless-nonroot-container-images.md) | Distroless nonroot container images | `Accepted` | N/A | N/A | N/A |
| [ADR-0008](0008-generate-sbom-in-ci.md) | Generate CycloneDX SBOM in CI | `Accepted` | 2026-10-27 | N/A | ADR-0001 |
| [ADR-0009](0009-client-nonzero-exit-code.md) | Exit with non-zero status code on client enrollment error | `Accepted` | 2026-11-05 | N/A | ADR-0002 |
| [ADR-0010](0010-use-shared-gitleaks-secret-scan-workflow.md) | Use the Shared Gitleaks Secret-Scan Workflow | `Accepted` | 2026-11-12 | N/A | N/A |
