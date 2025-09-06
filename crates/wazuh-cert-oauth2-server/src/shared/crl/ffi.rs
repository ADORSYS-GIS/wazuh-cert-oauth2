use std::time::{SystemTime, UNIX_EPOCH};

use foreign_types::ForeignTypeRef;
use openssl::pkey::PKey;
use openssl::x509::X509Ref;
use openssl_sys as ffi;
use tracing::{debug, info};
use wazuh_cert_oauth2_model::models::errors::{AppError, AppResult};

use super::RevocationEntry;

pub(crate) unsafe fn create_crl() -> AppResult<*mut ffi::X509_CRL> {
    unsafe {
        debug!("Creating new X509_CRL");
        let crl = ffi::X509_CRL_new();
        if crl.is_null() {
            return Err(AppError::CrlFfi {
                func: "X509_CRL_new",
            });
        }
        debug!("Created X509_CRL pointer: {:?}", crl);
        Ok(crl)
    }
}

pub(crate) unsafe fn set_version_and_issuer(
    crl: *mut ffi::X509_CRL,
    ca_cert: &X509Ref,
) -> AppResult<()> {
    unsafe {
        debug!("Setting CRL version to v2 and issuer name from CA");
        if ffi::X509_CRL_set_version(crl, 1) != 1 {
            return Err(AppError::CrlFfi {
                func: "X509_CRL_set_version",
            });
        }
        let issuer = ffi::X509_get_subject_name(ca_cert.as_ptr());
        if issuer.is_null() {
            return Err(AppError::CrlFfi {
                func: "X509_get_subject_name",
            });
        }
        if ffi::X509_CRL_set_issuer_name(crl, issuer) != 1 {
            return Err(AppError::CrlFfi {
                func: "X509_CRL_set_issuer_name",
            });
        }
        debug!("CRL issuer set successfully");
        Ok(())
    }
}

pub(crate) unsafe fn set_times_now_and_next(crl: *mut ffi::X509_CRL) -> AppResult<()> {
    unsafe {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        debug!(
            "Setting CRL lastUpdate={} nextUpdate={} (seconds since epoch)",
            now,
            now + 86400
        );
        let last_ptr = ffi::ASN1_TIME_new();
        if last_ptr.is_null() {
            return Err(AppError::CrlFfi {
                func: "ASN1_TIME_new",
            });
        }
        let next_ptr = ffi::ASN1_TIME_new();
        if next_ptr.is_null() {
            return Err(AppError::CrlFfi {
                func: "ASN1_TIME_new",
            });
        }
        if ffi::ASN1_TIME_set(last_ptr, now as _).is_null() {
            return Err(AppError::CrlFfi {
                func: "ASN1_TIME_set",
            });
        }
        if ffi::ASN1_TIME_set(next_ptr, (now + 86400) as _).is_null() {
            return Err(AppError::CrlFfi {
                func: "ASN1_TIME_set",
            });
        }
        if ffi::X509_CRL_set1_lastUpdate(crl, last_ptr) != 1 {
            ffi::ASN1_TIME_free(last_ptr);
            ffi::ASN1_TIME_free(next_ptr);
            return Err(AppError::CrlFfi {
                func: "X509_CRL_set1_lastUpdate",
            });
        }
        if ffi::X509_CRL_set1_nextUpdate(crl, next_ptr) != 1 {
            ffi::ASN1_TIME_free(last_ptr);
            ffi::ASN1_TIME_free(next_ptr);
            return Err(AppError::CrlFfi {
                func: "X509_CRL_set1_nextUpdate",
            });
        }
        ffi::ASN1_TIME_free(last_ptr);
        ffi::ASN1_TIME_free(next_ptr);
        debug!("CRL validity window set successfully");
        Ok(())
    }
}

pub(crate) unsafe fn add_revocations(
    crl: *mut ffi::X509_CRL,
    entries_snapshot: Vec<RevocationEntry>,
) -> AppResult<()> {
    unsafe {
        info!("Adding {} revocation entries", entries_snapshot.len());
        for e in entries_snapshot {
            debug!(
                "Adding revocation: serial={} reason={:?} revoked_at_unix={}",
                e.serial_hex, e.reason, e.revoked_at_unix
            );
            let rev = ffi::X509_REVOKED_new();
            if rev.is_null() {
                return Err(AppError::CrlFfi {
                    func: "X509_REVOKED_new",
                });
            }
            let bn = openssl::bn::BigNum::from_hex_str(&e.serial_hex)?;
            let ai_null: *mut ffi::ASN1_INTEGER = std::ptr::null_mut();
            let ai = ffi::BN_to_ASN1_INTEGER(bn.as_ptr(), ai_null);
            if ai.is_null() {
                return Err(AppError::CrlFfi {
                    func: "BN_to_ASN1_INTEGER",
                });
            }
            if ffi::X509_REVOKED_set_serialNumber(rev, ai) != 1 {
                return Err(AppError::CrlFfi {
                    func: "X509_REVOKED_set_serialNumber",
                });
            }
            let when_ptr = ffi::ASN1_TIME_new();
            if when_ptr.is_null() {
                return Err(AppError::CrlFfi {
                    func: "ASN1_TIME_new",
                });
            }
            if ffi::ASN1_TIME_set(when_ptr, e.revoked_at_unix as _).is_null() {
                return Err(AppError::CrlFfi {
                    func: "ASN1_TIME_set",
                });
            }
            if ffi::X509_REVOKED_set_revocationDate(rev, when_ptr) != 1 {
                ffi::ASN1_TIME_free(when_ptr);
                return Err(AppError::CrlFfi {
                    func: "X509_REVOKED_set_revocationDate",
                });
            }
            if ffi::X509_CRL_add0_revoked(crl, rev) != 1 {
                return Err(AppError::CrlFfi {
                    func: "X509_CRL_add0_revoked",
                });
            }
        }
        debug!("All revocation entries added");
        Ok(())
    }
}

pub(crate) unsafe fn sort_and_sign(
    crl: *mut ffi::X509_CRL,
    ca_key: &PKey<openssl::pkey::Private>,
) -> AppResult<()> {
    unsafe {
        debug!("Sorting CRL entries");
        if ffi::X509_CRL_sort(crl) != 1 {
            return Err(AppError::CrlFfi {
                func: "X509_CRL_sort",
            });
        }
        info!("Signing CRL with SHA-256");
        let md = ffi::EVP_sha256();
        if ffi::X509_CRL_sign(crl, ca_key.as_ptr(), md) == 0 {
            return Err(AppError::CrlFfi {
                func: "X509_CRL_sign",
            });
        }
        debug!("CRL signed successfully");
        Ok(())
    }
}

pub(crate) unsafe fn encode_der_and_free(crl: *mut ffi::X509_CRL) -> AppResult<Vec<u8>> {
    unsafe {
        debug!("Encoding CRL to DER");
        let mut buf: *mut u8 = std::ptr::null_mut();
        let len = ffi::i2d_X509_CRL(crl, &mut buf as *mut *mut u8);
        if len <= 0 || buf.is_null() {
            return Err(AppError::CrlFfi {
                func: "i2d_X509_CRL",
            });
        }
        let out = std::slice::from_raw_parts(buf as *const u8, len as usize).to_vec();
        ffi::OPENSSL_free(buf as *mut _);
        ffi::X509_CRL_free(crl);
        debug!("Encoded DER length: {} bytes", out.len());
        Ok(out)
    }
}
