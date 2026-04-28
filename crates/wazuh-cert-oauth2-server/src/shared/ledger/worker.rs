use super::LedgerEntry;
use super::csv::persist_csv;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};
use wazuh_cert_oauth2_model::models::errors::AppResult;

// Re-export to preserve worker::Command and worker::load_entries API
pub(super) use super::commands::Command;
pub(super) use super::loader::load_entries;

pub fn spawn_ledger_worker(
    inner: Arc<RwLock<Vec<LedgerEntry>>>,
    path: PathBuf,
    mut rx: mpsc::Receiver<Command>,
) {
    tokio::spawn(async move { ledger_worker(inner, path, &mut rx).await });
}

async fn ledger_worker(
    inner: Arc<RwLock<Vec<LedgerEntry>>>,
    path: PathBuf,
    rx: &mut mpsc::Receiver<Command>,
) {
    while let Some(cmd) = rx.recv().await {
        match cmd {
            Command::RecordIssued {
                subject,
                serial_hex,
                issued_at_unix,
                issuer,
                realm,
                respond_to,
            } => {
                let res = apply_record_issued(
                    &inner,
                    &path,
                    subject,
                    serial_hex,
                    issued_at_unix,
                    issuer,
                    realm,
                )
                .await;
                let _ = respond_to.send(res);
            }
            Command::MarkRevoked {
                serial_hex,
                reason,
                revoked_at_unix,
                respond_to,
            } => {
                let res =
                    apply_mark_revoked(&inner, &path, serial_hex, reason, revoked_at_unix).await;
                let _ = respond_to.send(res);
            }
            Command::CheckAndRevokeActive {
                subject,
                overwrite,
                revoked_at_unix,
                respond_to,
            } => {
                let res = apply_check_and_revoke_active(
                    &inner,
                    &path,
                    &subject,
                    overwrite,
                    revoked_at_unix,
                )
                .await;
                let _ = respond_to.send(res);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn apply_record_issued(
    inner: &Arc<RwLock<Vec<LedgerEntry>>>,
    path: &PathBuf,
    subject: String,
    serial_hex: String,
    issued_at_unix: u64,
    issuer: Option<String>,
    realm: Option<String>,
) -> AppResult<()> {
    {
        let mut guard = inner.write().await;
        guard.push(LedgerEntry {
            subject,
            serial_hex,
            issued_at_unix,
            revoked: false,
            revoked_at_unix: None,
            reason: None,
            issuer,
            realm,
        });
    }
    persist_csv(path, inner).await
}

async fn apply_mark_revoked(
    inner: &Arc<RwLock<Vec<LedgerEntry>>>,
    path: &PathBuf,
    serial_hex: String,
    reason: Option<String>,
    revoked_at_unix: u64,
) -> AppResult<()> {
    {
        let mut guard = inner.write().await;
        if let Some(entry) = guard
            .iter_mut()
            .rev()
            .find(|e| e.serial_hex.eq_ignore_ascii_case(&serial_hex))
        {
            if !entry.revoked {
                entry.revoked = true;
                entry.revoked_at_unix = Some(revoked_at_unix);
                entry.reason = reason.clone();
            }
        } else {
            guard.push(LedgerEntry {
                subject: String::new(),
                serial_hex,
                issued_at_unix: 0,
                revoked: true,
                revoked_at_unix: Some(revoked_at_unix),
                reason: reason.clone(),
                issuer: None,
                realm: None,
            });
        }
    }
    persist_csv(path, inner).await
}

async fn apply_check_and_revoke_active(
    inner: &Arc<RwLock<Vec<LedgerEntry>>>,
    path: &PathBuf,
    subject: &str,
    overwrite: bool,
    revoked_at_unix: u64,
) -> AppResult<()> {
    use wazuh_cert_oauth2_model::models::errors::AppError;

    let active_serials: Vec<String> = {
        let guard = inner.read().await;
        guard
            .iter()
            .filter(|e| e.subject == subject && !e.revoked)
            .map(|e| e.serial_hex.clone())
            .collect()
    };

    if active_serials.is_empty() {
        return Ok(());
    }

    if !overwrite {
        return Err(AppError::Conflict(
            "User already has an active certificate. Use the --overwrite flag to re-enroll and replace it.".to_string(),
        ));
    }

    {
        let mut guard = inner.write().await;
        for entry in guard
            .iter_mut()
            .filter(|e| e.subject == subject && !e.revoked)
        {
            entry.revoked = true;
            entry.revoked_at_unix = Some(revoked_at_unix);
            entry.reason = Some("auto-rotate (one cert per user)".to_string());
        }
    }

    persist_csv(path, inner).await
}
