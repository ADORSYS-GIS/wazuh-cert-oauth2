use std::path::PathBuf;
use std::sync::Arc;

use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use tokio::fs;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info};
use wazuh_cert_oauth2_model::models::errors::AppResult;

use super::RevocationEntry;
use super::ffi;

pub(super) enum Command {
    Rebuild {
        ca_cert: Arc<X509>,
        ca_key: Arc<PKey<Private>>,
        entries_snapshot: Vec<RevocationEntry>,
        respond_to: oneshot::Sender<AppResult<()>>,
    },
}

pub(super) fn spawn_crl_worker(path: PathBuf, mut rx: mpsc::Receiver<Command>) {
    tokio::spawn(async move {
        while let Some(cmd) = rx.recv().await {
            match cmd {
                Command::Rebuild {
                    ca_cert,
                    ca_key,
                    entries_snapshot,
                    respond_to,
                } => {
                    let res = apply_rebuild(&path, &ca_cert, &ca_key, entries_snapshot).await;
                    let _ = respond_to.send(res);
                }
            }
        }
    });
}

async fn apply_rebuild(
    path: &PathBuf,
    ca_cert: &X509,
    ca_key: &PKey<Private>,
    entries_snapshot: Vec<RevocationEntry>,
) -> AppResult<()> {
    info!(
        "Rebuilding CRL with {} revocation entries",
        entries_snapshot.len()
    );
    let started = std::time::Instant::now();
    let bytes: Vec<u8> = unsafe {
        let crl = ffi::create_crl()?;
        ffi::set_version_and_issuer(crl, ca_cert.as_ref())?;
        ffi::set_times_now_and_next(crl)?;
        ffi::add_revocations(crl, entries_snapshot)?;
        ffi::sort_and_sign(crl, ca_key)?;
        ffi::encode_der_and_free(crl)?
    };
    let tmp = path.with_extension("crl.tmp");
    debug!(
        "Writing CRL ({} bytes) to temporary file: {}",
        bytes.len(),
        tmp.display()
    );
    fs::write(&tmp, &bytes).await?;
    fs::rename(tmp, path).await?;
    info!(
        "CRL updated at {} (took {:?})",
        path.display(),
        started.elapsed()
    );
    Ok(())
}
