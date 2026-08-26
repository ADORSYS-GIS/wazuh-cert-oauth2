use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use rand::TryRng;
use tracing::{debug, error, warn};
use unwrap_infallible::UnwrapInfallible;
use wazuh_cert_oauth2_model::models::errors::AppResult;

use super::{ClaimedItem, SpoolItem, SpoolStore, is_json, now_unix};

/// On-disk JSON directory spool (local-dev / tests / fallback).
///
/// Claiming renames a `.json` file to `.processing` so it is not re-claimed
/// while being processed; `unclaim` renames it back so failed items are
/// retried on the next cycle. Not-yet-due evictions are skipped so they don't
/// block the rest of the spool.
pub struct DirSpoolStore {
    dir: PathBuf,
    dead_letter_dir: PathBuf,
}

impl DirSpoolStore {
    pub fn new(dir: PathBuf, dead_letter_dir: PathBuf) -> Self {
        Self {
            dir,
            dead_letter_dir,
        }
    }
}

#[async_trait]
impl SpoolStore for DirSpoolStore {
    async fn enqueue(
        &self,
        item: SpoolItem,
        _triggered_at_unix: u64,
        _delete_after_unix: Option<u64>,
    ) -> AppResult<()> {
        let data = serde_json::to_vec(&item)?;
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let mut buf = [0u8; 8];
        rand::rng().try_fill_bytes(&mut buf).unwrap_infallible();
        let mut rid = String::with_capacity(buf.len() * 2);
        for b in buf {
            rid.push_str(&format!("{:02x}", b));
        }
        let filename = format!("{}-{}-{}.json", item.item_type(), ms, rid);
        let path = self.dir.join(&filename);
        let tmp = self.dir.join(format!("{}.tmp", filename));
        tokio::fs::write(&tmp, data).await?;
        tokio::fs::rename(&tmp, &path).await?;
        Ok(())
    }

    async fn claim_next(&self) -> AppResult<Option<ClaimedItem>> {
        let mut dir = match tokio::fs::read_dir(&self.dir).await {
            Ok(d) => d,
            Err(e) => {
                warn!("spool read_dir failed: {}", e);
                return Ok(None);
            }
        };
        while let Some(entry) = dir.next_entry().await? {
            let path = entry.path();
            if !is_json(&path) {
                continue;
            }
            let bytes = match tokio::fs::read(&path).await {
                Ok(b) => b,
                Err(e) => {
                    warn!("failed to read {}: {}", path.display(), e);
                    continue;
                }
            };
            let item: SpoolItem = match serde_json::from_slice(&bytes) {
                Ok(item) => item,
                Err(e) => {
                    warn!("invalid spool item {}; deleting: {}", path.display(), e);
                    let _ = tokio::fs::remove_file(&path).await;
                    continue;
                }
            };
            // Skip not-yet-due evictions so they don't block the rest of the spool.
            if let SpoolItem::EvictRequest { req } = &item
                && let Some(delete_after) = req.delete_after_unix
                && now_unix() < delete_after
            {
                debug!("eviction for {} not yet due; skipping", req.subject);
                continue;
            }
            // Claim by renaming to `.processing` so it isn't re-claimed.
            let processing = path.with_extension("processing");
            tokio::fs::rename(&path, &processing).await?;
            let triggered_at_unix = match &item {
                SpoolItem::EvictRequest { req } => req.triggered_at_unix,
                _ => now_unix(),
            };
            return Ok(Some(ClaimedItem {
                id: processing.to_string_lossy().to_string(),
                item,
                triggered_at_unix,
            }));
        }
        Ok(None)
    }

    async fn mark_done(&self, id: &str) -> AppResult<()> {
        let path = PathBuf::from(id);
        debug!("successfully processed {}; removing", path.display());
        tokio::fs::remove_file(&path).await?;
        Ok(())
    }

    async fn mark_dead_letter(&self, id: &str, _error: &str) -> AppResult<()> {
        let processing = PathBuf::from(id);
        let now = now_unix();
        // Keep a `.json` extension in the DLQ so the item stays inspectable.
        let dlq_filename = format!(
            "{}-{}.json",
            now,
            processing.file_stem().unwrap_or_default().to_string_lossy()
        );
        let dlq_path = self.dead_letter_dir.join(&dlq_filename);
        error!(
            path = %processing.display(),
            dead_letter_path = %dlq_path.display(),
            "Moving expired spool item to dead-letter directory",
        );
        tokio::fs::rename(&processing, &dlq_path).await?;
        Ok(())
    }

    async fn update_item(
        &self,
        id: &str,
        item: &SpoolItem,
        _delete_after_unix: Option<u64>,
    ) -> AppResult<()> {
        let processing = PathBuf::from(id);
        let data = serde_json::to_vec(item)?;
        let tmp = processing.with_extension("json.tmp");
        tokio::fs::write(&tmp, &data).await?;
        // Rename back to `.json` so the item can be re-claimed (e.g. after the
        // grace deadline elapses).
        let json_path = processing.with_extension("json");
        tokio::fs::rename(&tmp, &json_path).await?;
        Ok(())
    }

    async fn unclaim(&self, id: &str) -> AppResult<()> {
        let processing = PathBuf::from(id);
        let json_path = processing.with_extension("json");
        tokio::fs::rename(&processing, &json_path).await?;
        Ok(())
    }
}
