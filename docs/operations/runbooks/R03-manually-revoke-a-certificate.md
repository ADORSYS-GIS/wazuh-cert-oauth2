# R03: Manually revoke a certificate

**Symptom:** A certificate must be revoked immediately (e.g. suspected compromise, offboarding).

**Steps:**

  1. Identify the certificate by serial or subject from the ledger.

  2. Call the server API with a valid OIDC bearer token:
         
```
curl -X POST https://<server>/api/revoke \
-H "Authorization: Bearer <token>" \
-H "Content-Type: application/json" \
-d '{"serial_hex":"<serial>"}'
```

  3. The server marks the ledger entry and rebuilds the CRL.

  4. If the agent must be removed from the manager, trigger an eviction (or rely on the automated path).

**Notes:** Manual revokes are not separately audit-logged beyond the ledger.
---
