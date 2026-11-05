# ADR-0002: Exit with non-zero status code on client enrollment error

> The client terminates with exit code 1 when enrollment fails, so callers and wrappers can detect the failure from the process exit status.

## Metadata

| Field | Value |
| :--- | :--- |
| **Document ID** | ADR-0002 |
| **Status** | `Accepted` |
| **Date** | 2026-11-05 |
| **Deciders** | Wazuh maintainers |
| **Governs** | `crates/wazuh-cert-oauth2-client/src/main.rs` |
| **Amends** | N/A |
| **Amended by** | N/A |
| **Supersedes** | N/A |
| **Superseded by** | N/A |

## Context

The `wazuh-cert-oauth2-client` executable runs the enrollment flow in `app().await` and handles errors via a match expression. When `app().await` returns `Err(e)` (for example, an upstream HTTP 409 Conflict, a network failure, or an invalid token), the error was logged with `error!`, but execution fell off the end of `main()` and the process terminated with exit code 0.

Callers and wrappers — such as the Wazuh Agent installer GUI or automation scripts that monitor process exit codes — therefore concluded that enrollment succeeded even when it failed. Shell scripts relying on `set -e` or `$?` continued downstream execution despite missing certificates and keys.

The deciding forces were: callers must be able to detect enrollment failure from the process exit status, successful runs must keep exiting with code 0, and the failure path must be verifiable by tests.

## Decision

We will make `wazuh-cert-oauth2-client` terminate with exit code 1 when `app().await` returns `Err(e)`, by calling `std::process::exit(1)` in the error branch of the match in `main()` after logging the error. Successful execution continues to exit with code 0.

## Options considered

| Option | Verdict | Why (one line) |
| :--- | :--- | :--- |
| Exit with code 1 on error | Adopted | Lets callers and wrappers detect failure from the exit status. |
| Log the error and exit 0 (status quo) | Rejected | Callers cannot distinguish success from failure. |
| Return a `Result` from `main` | Rejected | `#[tokio::main]` does not propagate a non-zero exit code from a returned `Result`. |

## Consequences

**Not part of this decision:** the exit code used for clap argument-parsing errors (clap exits with its own code), and the exit codes of the other binaries in this workspace.

### Impact

**Benefits**
- Automated callers and GUI wrappers can detect enrollment failure from the process exit code.
- Shell scripts using `set -e` or `$?` no longer continue silently after a failed enrollment.

**Costs**
- Adds an explicit process exit on the error path.

**Risks**
- None beyond the intended behavior change on the error path.

### Accepted limits

- The exit code is a coarse signal; it does not distinguish between failure causes (network, conflict, invalid token). Distinguishing causes is a separate decision.

### Done when

- [x] `wazuh-cert-oauth2-client` terminates with exit code 1 when `app().await` returns an error.
- [x] Successful execution continues to exit with code 0.
- [x] An integration test verifies a non-zero exit code on simulated failure.

### Revisit when

- The client's error-handling or process-exit behavior changes.

## Rollback

Nothing to roll back.

## Solution implementation

| Kind | Tracking | Status | What it covers |
| :--- | :--- | :--- | :--- |
| Issue | [ADORSYS-GIS/wazuh-cert-oauth2#386](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/issues/386) | Closed | Reports the exit-code-0 bug |
| PR | [ADORSYS-GIS/wazuh-cert-oauth2#397](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/pull/397) | Merged 2026-11-05 | Adds the exit-code fix and this ADR |
| Commit | [3977165](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/3977165d427f0861fa2271d7f69109cff6bee395) | 2026-11-05 | Merge commit for PR #397 |
