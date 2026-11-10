# R08: Wazuh Manager API unreachable (evictions failing)

**Symptom:** Agent evictions are not completing; eviction requests stay in the spool.

**Steps:**

  1. Confirm the Wazuh Manager API is reachable from the webhook.

  2. Confirm the Wazuh API credentials are valid and TLS verification passes (the Root CA certificate is used as the CA bundle).

  3. Confirm eviction requests are being retried with backoff and not dead-lettered prematurely.

  4. Once the manager is reachable, verify pending evictions drain.

**Notes:** Evictions are retried with exponential backoff and dead-lettered after the TTL. Auto-rotate evictions skip the grace period.
---
