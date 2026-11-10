# R06: Restore the ledger / CRL from backup

**Symptom:** The ledger or CRL is lost or corrupted and must be restored.

**Steps:**

  1. Restore the storage that holds the ledger and CRL (PostgreSQL database, or the on-disk CSV/JSON fallback).

  2. If restoring from a CSV ledger into PostgreSQL, use the `import-ledger` subcommand.

  3. Verify the CRL is rebuilt from the restored ledger's revoked entries.

  4. Confirm the nginx sidecar picks up the restored CRL.

**Notes:** No RPO/RTO is defined and restore is untested end-to-end. The Root CA key is not part of this backup, see [R09](./R09-root-ca-key-compromise-or-loss.md).
---
