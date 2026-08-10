---
layout: default
title: Reliability & spooling
parent: Features
nav_order: 5
---

# Reliability & spooling

The Webhook Proxy guarantees that revocation and eviction actions are eventually delivered even when upstream services (the certificate server or Wazuh manager) are temporarily unavailable, using disk-backed **spooling**.

## How spooling works

- Outbound requests (revocations, evictions, GitHub tickets) are written to a **spool directory** (`--spool-dir`, default `/data/spool`) before or when delivery fails.
- A background processor scans the spool on an interval (`--spool-interval-secs`) and retries with **exponential backoff** (`--retry-attempts`, `--retry-base-ms`, `--retry-max-ms`).
- File rewrites are **atomic** (temp-file + rename) so a crash mid-write never corrupts a queued item.

## Eviction TTL & dead-lettering

- Eviction spool items older than the TTL (`SPOOL_EVICT_TTL_SECS`, default 86400s / 24h) are **moved to a dead-letter directory** (`SPOOL_DEAD_LETTER_DIR`, default `dead-letter/` sibling of `SPOOL_DIR`) with an `error!` log.
- This prevents unbounded retry of poison messages while preserving the item for operator **inspection or replay**.
- Safety constraints: the dead-letter directory must **not** be the same as `SPOOL_DIR`, and should live on the **same filesystem/volume** as the spool to allow atomic rename.

## Persistence

Mount a writable volume at `/data` (or adjust `--spool-dir`) so the spool survives process restarts and host outages.

## Why it matters

Because revocations and evictions are security-critical, they can't be fire-and-forget. Spooling gives **at-least-once delivery** with bounded retry, so a certificate that must be revoked is revoked as soon as the system can reach the server.
