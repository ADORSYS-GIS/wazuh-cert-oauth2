# R07: Server or webhook is down

**Symptom:** The server or webhook process is crash-looping or unavailable.

**Steps:**

  1. Check the process status and the startup/readiness/liveness probes (the `healthcheck` binary).

  2. Check logs (`RUST_LOG` controls verbosity; default `info`).

  3. Confirm the OIDC issuer and (for the webhook) the server base URL are reachable.

  4. Restart the server or webhook, or roll back to the previous version.

**Notes:** Health probes restart a dead process; external monitoring is required to page. Revocations are spooled while the server is down and delivered on recovery.
---
