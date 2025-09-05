use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use openssl_sys as ffi;
use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::pkey::PKey;
use openssl::x509::X509Ref;
use tokio::fs;
use wazuh_cert_oauth2_model::models::errors::AppError;

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
        // The CRL state is now stateless with respect to revocation DB.
        Ok(Self { crl_file_path })
    }

    /// Read the CRL bytes from the configured path.
    pub async fn read_crl_file(&self) -> Result<Vec<u8>> {
        let data = fs::read(&self.crl_file_path).await?;
        Ok(data)
    }

    /// Rebuild the CRL DER bytes from the provided revocation snapshot and write atomically to CRL_PATH.
    pub async fn rebuild_crl_from(&self, ca_cert: &X509Ref, ca_key: &PKey<openssl::pkey::Private>, entries_snapshot: Vec<RevocationEntry>) -> Result<()> {
        let bytes: Vec<u8> = unsafe {
            let crl = ffi::X509_CRL_new();
            if crl.is_null() { anyhow::bail!(AppError::CrlFfi { func: "X509_CRL_new" }); }

            // version 1 (v2 CRL)
            if ffi::X509_CRL_set_version(crl, 1) != 1 { anyhow::bail!(AppError::CrlFfi { func: "X509_CRL_set_version" }); }

            // issuer
            let issuer = ffi::X509_get_subject_name(ca_cert.as_ptr());
            if issuer.is_null() { anyhow::bail!(AppError::CrlFfi { func: "X509_get_subject_name" }); }
            if ffi::X509_CRL_set_issuer_name(crl, issuer) != 1 { anyhow::bail!(AppError::CrlFfi { func: "X509_CRL_set_issuer_name" }); }

            // lastUpdate = now; nextUpdate = now + 1 day
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
            let last_ptr = ffi::ASN1_TIME_new();
            if last_ptr.is_null() { anyhow::bail!(AppError::CrlFfi { func: "ASN1_TIME_new" }); }
            let next_ptr = ffi::ASN1_TIME_new();
            if next_ptr.is_null() { anyhow::bail!(AppError::CrlFfi { func: "ASN1_TIME_new" }); }
            if ffi::ASN1_TIME_set(last_ptr, now as _) .is_null() { anyhow::bail!(AppError::CrlFfi { func: "ASN1_TIME_set" }); }
            if ffi::ASN1_TIME_set(next_ptr, (now + 86400) as _) .is_null() { anyhow::bail!(AppError::CrlFfi { func: "ASN1_TIME_set" }); }

            // Use set1 (copies), then free our temp times
            let r1 = ffi::X509_CRL_set1_lastUpdate(crl, last_ptr);
            if r1 != 1 { ffi::ASN1_TIME_free(last_ptr); ffi::ASN1_TIME_free(next_ptr); anyhow::bail!(AppError::CrlFfi { func: "X509_CRL_set1_lastUpdate" }); }
            let r2 = ffi::X509_CRL_set1_nextUpdate(crl, next_ptr);
            if r2 != 1 { ffi::ASN1_TIME_free(last_ptr); ffi::ASN1_TIME_free(next_ptr); anyhow::bail!(AppError::CrlFfi { func: "X509_CRL_set1_nextUpdate" }); }
            ffi::ASN1_TIME_free(last_ptr);
            ffi::ASN1_TIME_free(next_ptr);

            // Add revoked entries
            for e in entries_snapshot {
                let rev = ffi::X509_REVOKED_new();
                if rev.is_null() { anyhow::bail!(AppError::CrlFfi { func: "X509_REVOKED_new" }); }

                // serial_hex -> BIGNUM -> ASN1_INTEGER
                let bn = openssl::bn::BigNum::from_hex_str(&e.serial_hex)?;
                let ai_null: *mut ffi::ASN1_INTEGER = std::ptr::null_mut();
                let ai = ffi::BN_to_ASN1_INTEGER(bn.as_ptr(), ai_null);
                if ai.is_null() { anyhow::bail!(AppError::CrlFfi { func: "BN_to_ASN1_INTEGER" }); }
                if ffi::X509_REVOKED_set_serialNumber(rev, ai) != 1 { anyhow::bail!(AppError::CrlFfi { func: "X509_REVOKED_set_serialNumber" }); }

                // revocation date
                let when_ptr = ffi::ASN1_TIME_new();
                if when_ptr.is_null() { anyhow::bail!(AppError::CrlFfi { func: "ASN1_TIME_new" }); }
                if ffi::ASN1_TIME_set(when_ptr, e.revoked_at_unix as _) .is_null() { anyhow::bail!(AppError::CrlFfi { func: "ASN1_TIME_set" }); }
                if ffi::X509_REVOKED_set_revocationDate(rev, when_ptr) != 1 { ffi::ASN1_TIME_free(when_ptr); anyhow::bail!(AppError::CrlFfi { func: "X509_REVOKED_set_revocationDate" }); }
                // rev now owns when_ptr

                if ffi::X509_CRL_add0_revoked(crl, rev) != 1 { anyhow::bail!(AppError::CrlFfi { func: "X509_CRL_add0_revoked" }); }
                // rev is now owned by crl
            }

            // sort and sign
            if ffi::X509_CRL_sort(crl) != 1 { anyhow::bail!(AppError::CrlFfi { func: "X509_CRL_sort" }); }
            let md = ffi::EVP_sha256();
            if ffi::X509_CRL_sign(crl, ca_key.as_ptr(), md) == 0 { anyhow::bail!(AppError::CrlFfi { func: "X509_CRL_sign" }); }

            // i2d -> Vec<u8>
            let mut buf: *mut u8 = std::ptr::null_mut();
            let len = ffi::i2d_X509_CRL(crl, &mut buf as *mut *mut u8);
            if len <= 0 || buf.is_null() { anyhow::bail!(AppError::CrlFfi { func: "i2d_X509_CRL" }); }
            let out = std::slice::from_raw_parts(buf as *const u8, len as usize).to_vec();
            // OpenSSL allocs via OPENSSL_malloc; free buffer and crl
            ffi::OPENSSL_free(buf as *mut _);
            ffi::X509_CRL_free(crl);
            out
        };

        // Write atomically (after FFI pointers dropped)
        let tmp = self.crl_file_path.with_extension("crl.tmp");
        fs::write(&tmp, &bytes).await?;
        fs::rename(tmp, &self.crl_file_path).await?;
        Ok(())
    }
}
