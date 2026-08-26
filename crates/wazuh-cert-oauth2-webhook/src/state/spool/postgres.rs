use async_trait::async_trait;
use sqlx::PgPool;
use wazuh_cert_oauth2_model::models::errors::AppResult;

use super::{ClaimedItem, SpoolItem, SpoolStore, now_unix};

/// Postgres ENUM for the `spool_item.state` column.
#[derive(sqlx::Type, Debug, Clone, Copy)]
#[sqlx(type_name = "spool_state", rename_all = "snake_case")]
enum SpoolState {
    Pending,
    InProgress,
    Done,
    DeadLetter,
}

/// PostgreSQL `spool_item` table backend (system of record for multi-replica).
///
/// Claims use `SELECT ... FOR UPDATE SKIP LOCKED` so concurrent replicas can
/// process without double-delivery. Dead-lettering is in-table
/// (`state = 'dead_letter'`); no separate filesystem DLQ is required.
#[derive(Clone)]
pub struct PostgresSpoolStore {
    pool: PgPool,
}

impl PostgresSpoolStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SpoolStore for PostgresSpoolStore {
    async fn enqueue(
        &self,
        item: SpoolItem,
        triggered_at_unix: u64,
        delete_after_unix: Option<u64>,
    ) -> AppResult<()> {
        let payload = serde_json::to_value(&item)?;
        sqlx::query(
            "INSERT INTO spool_item (item_type, payload, state, triggered_at_unix, delete_after_unix)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(item.item_type())
        .bind(payload)
        .bind(SpoolState::Pending)
        .bind(triggered_at_unix as i64)
        .bind(delete_after_unix.map(|v| v as i64))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn claim_next(&self) -> AppResult<Option<ClaimedItem>> {
        let now = now_unix() as i64;
        let mut tx = self.pool.begin().await?;

        // Reclaim items left 'in_progress' by a crashed replica back to
        // 'pending' so they can be retried.
        sqlx::query(
            "UPDATE spool_item SET state = 'pending', updated_at = now()
             WHERE state = 'in_progress' AND updated_at < now() - interval '5 minutes'",
        )
        .execute(&mut *tx)
        .await?;

        // Atomically claim the next due pending item: set state = 'in_progress'
        // so concurrent replicas (SKIP LOCKED) never double-process it.
        let row: Option<(i64, serde_json::Value, i64)> = sqlx::query_as(
            "UPDATE spool_item SET state = 'in_progress', updated_at = now()
             WHERE id = (
                 SELECT id FROM spool_item
                 WHERE state = 'pending'
                   AND (delete_after_unix IS NULL OR delete_after_unix <= $1)
                 ORDER BY triggered_at_unix
                 LIMIT 1
                 FOR UPDATE SKIP LOCKED
             )
             RETURNING id, payload, triggered_at_unix",
        )
        .bind(now)
        .fetch_optional(&mut *tx)
        .await?;

        tx.commit().await?;

        let Some((id, payload, triggered_at_unix)) = row else {
            return Ok(None);
        };
        let item: SpoolItem = serde_json::from_value(payload)?;
        Ok(Some(ClaimedItem {
            id: id.to_string(),
            item,
            triggered_at_unix: triggered_at_unix as u64,
        }))
    }

    async fn mark_done(&self, id: &str) -> AppResult<()> {
        let id: i64 = id.parse()?;
        sqlx::query("DELETE FROM spool_item WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn mark_dead_letter(&self, id: &str, error: &str) -> AppResult<()> {
        let id: i64 = id.parse()?;
        sqlx::query(
            "UPDATE spool_item SET state = $2, last_error = $3, updated_at = now()
             WHERE id = $1",
        )
        .bind(id)
        .bind(SpoolState::DeadLetter)
        .bind(error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn update_item(
        &self,
        id: &str,
        item: &SpoolItem,
        delete_after_unix: Option<u64>,
    ) -> AppResult<()> {
        let id: i64 = id.parse()?;
        let payload = serde_json::to_value(item)?;
        // Set state back to 'pending' so the item can be re-claimed (e.g. after
        // the grace deadline elapses) instead of stalling in 'in_progress'.
        sqlx::query(
            "UPDATE spool_item SET payload = $2, delete_after_unix = $3, state = 'pending', updated_at = now()
             WHERE id = $1",
        )
        .bind(id)
        .bind(payload)
        .bind(delete_after_unix.map(|v| v as i64))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn unclaim(&self, _id: &str) -> AppResult<()> {
        // No-op: failed items stay 'in_progress' until the crash-recovery
        // reclaim returns them to 'pending' (avoids an immediate re-claim
        // busy-loop).
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::PostgresSpoolStore;
    use crate::state::spool::{EvictRequest, SpoolItem, SpoolStore};
    use std::collections::HashSet;
    use wazuh_cert_oauth2_model::models::revoke_request::RevokeRequest;

    /// Serializes the Postgres spool tests: they share the `spool_item` table
    /// and each clears it in setup, so they must not run concurrently.
    static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Connect to a real Postgres for integration tests. Skips when
    /// `TEST_DATABASE_URL` is not set (e.g. plain `cargo test`).
    async fn test_store() -> Option<PostgresSpoolStore> {
        let url = match std::env::var("TEST_DATABASE_URL") {
            Ok(u) => u,
            Err(_) => {
                eprintln!("TEST_DATABASE_URL not set; skipping spool Postgres test");
                return None;
            }
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(10)
            .connect(&url)
            .await
            .expect("connect to test database");
        wazuh_cert_oauth2_model::run_spool_migrations(&pool)
            .await
            .expect("run spool migrations");
        // Reset the table so tests are idempotent against a persistent DB.
        sqlx::query("DELETE FROM spool_item")
            .execute(&pool)
            .await
            .expect("clear spool_item");
        Some(PostgresSpoolStore::new(pool))
    }

    fn revoke(subject: &str) -> SpoolItem {
        SpoolItem::RevokeRequest {
            req: RevokeRequest {
                serial_hex: None,
                subject: Some(subject.to_string()),
                reason: Some("test".to_string()),
            },
        }
    }

    #[tokio::test]
    async fn postgres_enqueue_claim_done() {
        let _guard = TEST_LOCK.lock().await;
        let Some(store) = test_store().await else {
            return;
        };
        store
            .enqueue(revoke("u1"), 100, None)
            .await
            .expect("enqueue");

        let claimed = store.claim_next().await.expect("claim");
        let claimed = claimed.expect("item present");
        match claimed.item {
            SpoolItem::RevokeRequest { req } => assert_eq!(req.subject.as_deref(), Some("u1")),
            _ => panic!("expected revoke item"),
        }

        store.mark_done(&claimed.id).await.expect("mark done");
        assert!(
            store.claim_next().await.expect("claim").is_none(),
            "no items should remain after done"
        );
    }

    #[tokio::test]
    async fn postgres_atomic_claim_skip_locked() {
        let _guard = TEST_LOCK.lock().await;
        let Some(store) = test_store().await else {
            return;
        };
        for i in 0..3 {
            store
                .enqueue(revoke(&format!("u{i}")), 100 + i, None)
                .await
                .expect("enqueue");
        }

        // Claim concurrently — SKIP LOCKED must give each replica a distinct item.
        let mut handles = Vec::new();
        for _ in 0..3 {
            let store = store.clone();
            handles.push(tokio::spawn(async move {
                store.claim_next().await.expect("claim")
            }));
        }
        let mut ids: HashSet<String> = HashSet::new();
        for h in handles {
            if let Some(claimed) = h.await.expect("join") {
                assert!(ids.insert(claimed.id), "duplicate claim!");
            }
        }
        assert_eq!(ids.len(), 3, "all three items claimed distinctly");
    }

    #[tokio::test]
    async fn postgres_dead_letter_marks_state() {
        let _guard = TEST_LOCK.lock().await;
        let Some(store) = test_store().await else {
            return;
        };
        store
            .enqueue(
                SpoolItem::EvictRequest {
                    req: EvictRequest {
                        subject: "e1".to_string(),
                        wazuh_agent_name: None,
                        reason: "test".to_string(),
                        triggered_at_unix: 100,
                        agent_id: None,
                        delete_after_unix: None,
                    },
                },
                100,
                None,
            )
            .await
            .expect("enqueue");

        let claimed = store.claim_next().await.expect("claim").expect("item");
        store
            .mark_dead_letter(&claimed.id, "boom")
            .await
            .expect("dead letter");

        // Dead-lettered item is no longer claimable.
        assert!(store.claim_next().await.expect("claim").is_none());

        // And its state is recorded in the table.
        let id: i64 = claimed.id.parse().expect("id");
        let state: String = sqlx::query_scalar("SELECT state::text FROM spool_item WHERE id = $1")
            .bind(id)
            .fetch_one(&store.pool)
            .await
            .expect("query state");
        assert_eq!(state, "dead_letter");
    }
}
