# R02: Renew an expiring certificate

**Symptom:** An issued certificate is approaching or past its 1-year validity (no automated expiry alerting).

**Steps:**

  1. Re-run the client CLI (see [R01](./R01-enroll-a-new-agent.md)).

  2. If the recorded certificate is still **active** (not expired, not revoked), the server requires `--overwrite` to re-enroll; it revokes the previous active certificate and issues a new one (auto-rotate, [ADR-0006](../../adr/0006-auto-rotate-single-certificate-policy.md)).

  3. If the recorded certificate is **expired** , it is no longer considered active, a new certificate is issued directly, without `--overwrite` and without revoking the already-expired one.

  4. Confirm the new certificate is in place and the agent reconnects.

**Notes:** Renewal relies on re-enrollment. There is no automated expiry alerting yet. The "expired certificates no longer block re-enrollment" behaviour is the current implementation; the previous behaviour required `--overwrite` to replace an active certificate.
---
