# R05: Handle a webhook spool backlog or dead-letter

**Symptom:** Revocations or evictions are not being delivered; spool items accumulate or land in the dead-letter directory.

**Steps:**

  1. Check the spool directory (`SPOOL_DIR`) for pending items.

  2. Check the dead-letter directory for items older than the TTL (`SPOOL_EVICT_TTL_SECS`, default 24h).

  3. Inspect dead-letter items to determine why they failed (e.g. Wazuh Manager unreachable, bad agent name).

  4. Replay or re-queue valid items; discard poison messages.

  5. Confirm the upstream service (server or Wazuh Manager) is reachable before replaying.

**Notes:** Spooling gives at-least-once delivery [ADR-0005](../../adr/0005-webhook-spooling-for-at-least-once-delivery.md). Dead-lettering prevents unbounded retry of poison messages.
---
