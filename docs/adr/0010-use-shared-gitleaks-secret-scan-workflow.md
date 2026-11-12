# ADR-0010: Use the Shared Gitleaks Secret-Scan Workflow

> We replace the super-linter Gitleaks check (diff-based, no alerting) with the shared `adorsys-ci-cd-templates` secret-scan workflow, which scans the full git history and notifies the SIEM webhook on findings.

## Metadata

| Field             | Value                                                              |
| :---------------- | :----------------------------------------------------------------- |
| **Document ID**   | ADR-0010                                                           |
| **Status**        | `Accepted`                                                         |
| **Date**          | 2026-11-12                                                         |
| **Deciders**      | Wazuh maintainers                                                  |
| **Governs**       | `.github/workflows/sast.yml`, `.github/workflows/ci.yml`           |
| **Amends**        | N/A                                                                |
| **Amended by**    | N/A                                                                |
| **Supersedes**    | N/A                                                                |
| **Superseded by** | N/A                                                                |

## Context

`wazuh-cert-oauth2` previously ran Gitleaks through super-linter in the `lint` job of `.github/workflows/ci.yml` (`VALIDATE_GITLEAKS: "true"`). Super-linter's Gitleaks check scans the working tree / diff of the change, so it does not cover secrets already present in the commit history, and it has no alert routing.

The organization standardizes secret scanning on the shared `adorsys-ci-cd-templates/.github/workflows/secret-scan.yml` workflow, already used by `wazuh-suricata`, `global-gateway`, and other Wazuh repositories.

The deciding forces are:
- Scan the full commit history, not only the diff of a push or pull request, so secrets committed and later removed are still detected.
- Route findings to the SIEM team via a webhook.
- Reuse the shared workflow instead of a repository-local or super-linter check that drifts from the other Wazuh repositories.
- Pin the shared workflow to a commit SHA for supply-chain safety.

## Decision

We will add a `secret-scan` job to `.github/workflows/sast.yml` that calls the shared `ADORSYS-GIS/adorsys-ci-cd-templates/.github/workflows/secret-scan.yml` workflow, pinned to commit SHA `db2f1dbe7eb5efbcb06aa80ad3719fc1675c37bf`, on `ubuntu-latest`, passing `NOTIFY_WEBHOOK_URL`. The shared workflow scans the full git history (`--log-opts=--all`), uploads a SARIF report, and notifies the webhook on findings.

We will remove `VALIDATE_GITLEAKS` from the super-linter environment in `.github/workflows/ci.yml`, since the shared workflow now covers secret scanning. The other super-linter validations remain.

## Options considered

| Option | Verdict | Why (one line) |
| :--- | :--- | :--- |
| Shared `secret-scan.yml` workflow (adopted) | Adopted | Full-history scan, SIEM alerting, single source of truth, SHA-pinned. |
| Super-linter `VALIDATE_GITLEAKS` (status quo) | Rejected | Diff-based only, no alerting, drifts from the other Wazuh repositories. |
| GitHub native Secret scanning + Push protection | Rejected | Unavailable on a private repository on the free plan (API 404). |

## Consequences

**Not part of this decision:** GitHub native Secret scanning and Push protection (requires GitHub Advanced Security), and provisioning the `NOTIFY_WEBHOOK_URL` secret (the shared workflow skips notification gracefully when it is unset).

### Impact

**Benefits**
- Full git history is scanned on every run, so removed secrets are still found.
- Findings are routed to the SIEM webhook.
- Scanning is consistent across Wazuh repositories through the shared workflow.
- The shared workflow is pinned to a commit SHA, so a template change cannot be pulled in silently.

**Costs**
- The full-history scan fails on `main` until any pre-existing secrets are rotated or removed from history.
- `NOTIFY_WEBHOOK_URL` must be set at repo or org level for alerts to fire.

**Risks**
- The shared workflow changes behavior on a pin bump (mitigated by SHA pinning and review of the pin).
- A historical finding blocks the protected `main` branch until triaged.

### Accepted limits

- Native Secret scanning and Push protection remain unavailable on the free plan; the Gitleaks CI job is the equivalent coverage.
- The super-linter Gitleaks check is removed; the shared full-history scan is the single source of secret scanning.

### Done when

- [x] `secret-scan` job present in `.github/workflows/sast.yml`, pinned to a commit SHA of the shared workflow.
- [x] `VALIDATE_GITLEAKS` removed from the super-linter environment in `.github/workflows/ci.yml`.
- [x] ADR-0010 is documented and registered in `docs/adr/README.md`.

### Revisit when

- The shared `secret-scan.yml` workflow changes.
- The organization gains GitHub Advanced Security, enabling native scanning on private repositories.

## Rollback

**When.** The shared workflow fails on `main` because of a historical finding, or a pin bump breaks the scan.

**How, in order.**

1. Remove the `secret-scan` job from `.github/workflows/sast.yml` in its own commit.
2. Restore `VALIDATE_GITLEAKS: "true"` in the super-linter environment of `.github/workflows/ci.yml` in the same or a follow-up commit.
3. The other SAST jobs are unaffected and may stay.
4. The revert does not remove secrets already in history; those are cleared by rotation or history rewrite.

## Evidence

| Claim | Where |
| :--- | :--- |
| Shared secret scanning workflow | `ADORSYS-GIS/adorsys-ci-cd-templates/.github/workflows/secret-scan.yml` |
| Audit requirement and risk reference | Epic [ADORSYS-GIS/wazuh#2376](https://github.com/ADORSYS-GIS/wazuh/issues/2376) |
| The `secret-scan` job calls the shared workflow | `.github/workflows/sast.yml` in this repo |

## References

- [GitHub Secret scanning documentation](https://docs.github.com/en/code-security/secret-scanning)
- [adorsys-ci-cd-templates](https://github.com/ADORSYS-GIS/adorsys-ci-cd-templates)
- [ADR template](https://github.com/ADORSYS-GIS/wazuh/blob/main/docs/adr/template.md)
- [ADR writing guide](https://github.com/ADORSYS-GIS/wazuh/blob/main/docs/adr/GUIDE.md)

## Solution implementation

| Kind  | Tracking                                                                                             | Status | What it covers                                   |
| :---- | :--------------------------------------------------------------------------------------------------- | :----- | :----------------------------------------------- |
| Epic  | [ADORSYS-GIS/wazuh#2376](https://github.com/ADORSYS-GIS/wazuh/issues/2376)                           | Open   | Enable secret scanning across Wazuh repositories |
| Issue | [ADORSYS-GIS/wazuh-cert-oauth2#402](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/issues/402)     | Open   | Enable secret scanning and add Gitleaks CI       |
| PR    | [ADORSYS-GIS/wazuh-cert-oauth2#<PR>](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/pull/<PR>)     | Open   | Adds the `secret-scan` job and ADR-0010          |
