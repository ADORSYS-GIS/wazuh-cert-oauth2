use std::path::PathBuf;

use anyhow::Result;
use openssl::pkey::PKey;
use openssl::x509::X509Ref;
use serde::{Deserialize, Serialize};
use tokio::fs;
use log::{debug, info};

mod ffi;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEntry {
    pub serial_hex: String,
    pub reason: Option<String>,
    pub revoked_at_unix: u64,
}

pub struct CrlState {
    crl_file_path: PathBuf,
}

impl CrlState {
    pub async fn new(crl_file_path: PathBuf) -> Result<Self> {
        info!("Initialized CrlState with path: {}", crl_file_path.display());
        Ok(Self { crl_file_path })
    }

    pub async fn read_crl_file(&self) -> Result<Vec<u8>> {
        debug!("Reading CRL file from: {}", self.crl_file_path.display());
        let bytes = fs::read(&self.crl_file_path).await?;
        debug!("Read CRL file ({} bytes)", bytes.len());
        Ok(bytes)
    }

    pub async fn rebuild_crl_from(
        &self,
        ca_cert: &X509Ref,
        ca_key: &PKey<openssl::pkey::Private>,
        entries_snapshot: Vec<RevocationEntry>,
    ) -> Result<()> {
        info!(
            "Rebuilding CRL with {} revocation entries",
            entries_snapshot.len()
        );
        let started = std::time::Instant::now();
        let bytes: Vec<u8> = unsafe {
            let crl = ffi::create_crl()?;
            ffi::set_version_and_issuer(crl, ca_cert)?;
            ffi::set_times_now_and_next(crl)?;
            ffi::add_revocations(crl, entries_snapshot)?;
            ffi::sort_and_sign(crl, ca_key)?;
            ffi::encode_der_and_free(crl)?
        };
        let tmp = self.crl_file_path.with_extension("crl.tmp");
        debug!(
            "Writing CRL ({} bytes) to temporary file: {}",
            bytes.len(),
            tmp.display()
        );
        fs::write(&tmp, &bytes).await?;
        fs::rename(tmp, &self.crl_file_path).await?;
        info!(
            "CRL updated at {} (took {:?})",
            self.crl_file_path.display(),
            started.elapsed()
        );
        Ok(())
    }
}
