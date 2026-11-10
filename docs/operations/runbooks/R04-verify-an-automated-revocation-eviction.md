# R04: Verify an automated revocation / eviction

**Symptom:** A user was disabled or deleted in Keycloak; confirm the certificate was revoked and the agent evicted.

**Steps:**

  1. Confirm the webhook received the IdP event (webhook logs).

  2. Confirm the server marked the certificate revoked and rebuilt the CRL (ledger / CRL).

  3. Confirm the agent was removed from the Wazuh Manager (agent list).

  4. If the agent is still present, check the eviction spool for a pending or dead-lettered item (see [R05](./R05-handle-a-webhook-spool-backlog-or-dead-letter.md)).

**Notes:** For `USER-UPDATE`, revocation only fires when the user is disabled (`enabled: false`); re-enabling is ignored. Missing/unparseable representation fails safe to revocation.
---
