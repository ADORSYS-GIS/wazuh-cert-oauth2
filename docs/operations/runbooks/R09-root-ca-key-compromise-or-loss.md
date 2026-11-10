# R09: Root CA key compromise or loss

**Symptom:** The Root CA private key is suspected compromised or is lost.

**Steps:**

  1. **Treat as a security incident.** Suspend issuance and notify the SIEM team lead immediately.

  2. If compromised: assume all issued certificates are untrusted. Plan to re-issue the CA, re-enroll all agents, and revoke all previously issued certificates.

  3. If lost: no new certificates can be issued until a new CA is created and distributed.

  4. Document the incident and the recovery actions.

**Notes:** There is **no documented rotation or compromise procedure** yet. This runbook is a placeholder until that procedure is written and approved.
