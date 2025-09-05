use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use foreign_types::ForeignTypeRef;
use openssl::pkey::PKey;
use openssl::x509::X509Ref;
use openssl_sys as ffi;
use wazuh_cert_oauth2_model::models::errors::AppError;

use super::RevocationEntry;

#[inline]
pub(crate) unsafe fn create_crl() -> Result<*mut ffi::X509_CRL> { unsafe {
    let crl = ffi::X509_CRL_new();
    if crl.is_null() { anyhow::bail!(AppError::CrlFfi { func: "X509_CRL_new" }); }
    Ok(crl)
} }

#[inline]
pub(crate) unsafe fn set_version_and_issuer(crl: *mut ffi::X509_CRL, ca_cert: &X509Ref) -> Result<()> { unsafe {
    if ffi::X509_CRL_set_version(crl, 1) != 1 { anyhow::bail!(AppError::CrlFfi { func: "X509_CRL_set_version" }); }
    let issuer = ffi::X509_get_subject_name(ca_cert.as_ptr());
    if issuer.is_null() { anyhow::bail!(AppError::CrlFfi { func: "X509_get_subject_name" }); }
    if ffi::X509_CRL_set_issuer_name(crl, issuer) != 1 { anyhow::bail!(AppError::CrlFfi { func: "X509_CRL_set_issuer_name" }); }
    Ok(())
} }

#[inline]
pub(crate) unsafe fn set_times_now_and_next(crl: *mut ffi::X509_CRL) -> Result<()> { unsafe {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
    let last_ptr = ffi::ASN1_TIME_new();
    if last_ptr.is_null() { anyhow::bail!(AppError::CrlFfi { func: "ASN1_TIME_new" }); }
    let next_ptr = ffi::ASN1_TIME_new();
    if next_ptr.is_null() { anyhow::bail!(AppError::CrlFfi { func: "ASN1_TIME_new" }); }
    if ffi::ASN1_TIME_set(last_ptr, now as _).is_null() { anyhow::bail!(AppError::CrlFfi { func: "ASN1_TIME_set" }); }
    if ffi::ASN1_TIME_set(next_ptr, (now + 86400) as _).is_null() { anyhow::bail!(AppError::CrlFfi { func: "ASN1_TIME_set" }); }
    if ffi::X509_CRL_set1_lastUpdate(crl, last_ptr) != 1 { ffi::ASN1_TIME_free(last_ptr); ffi::ASN1_TIME_free(next_ptr); anyhow::bail!(AppError::CrlFfi { func: "X509_CRL_set1_lastUpdate" }); }
    if ffi::X509_CRL_set1_nextUpdate(crl, next_ptr) != 1 { ffi::ASN1_TIME_free(last_ptr); ffi::ASN1_TIME_free(next_ptr); anyhow::bail!(AppError::CrlFfi { func: "X509_CRL_set1_nextUpdate" }); }
    ffi::ASN1_TIME_free(last_ptr); ffi::ASN1_TIME_free(next_ptr); Ok(())
} }

#[inline]
pub(crate) unsafe fn add_revocations(crl: *mut ffi::X509_CRL, entries_snapshot: Vec<RevocationEntry>) -> Result<()> { unsafe {
    for e in entries_snapshot {
        let rev = ffi::X509_REVOKED_new();
        if rev.is_null() { anyhow::bail!(AppError::CrlFfi { func: "X509_REVOKED_new" }); }
        let bn = openssl::bn::BigNum::from_hex_str(&e.serial_hex)?;
        let ai_null: *mut ffi::ASN1_INTEGER = std::ptr::null_mut();
        let ai = ffi::BN_to_ASN1_INTEGER(bn.as_ptr(), ai_null);
        if ai.is_null() { anyhow::bail!(AppError::CrlFfi { func: "BN_to_ASN1_INTEGER" }); }
        if ffi::X509_REVOKED_set_serialNumber(rev, ai) != 1 { anyhow::bail!(AppError::CrlFfi { func: "X509_REVOKED_set_serialNumber" }); }
        let when_ptr = ffi::ASN1_TIME_new();
        if when_ptr.is_null() { anyhow::bail!(AppError::CrlFfi { func: "ASN1_TIME_new" }); }
        if ffi::ASN1_TIME_set(when_ptr, e.revoked_at_unix as _).is_null() { anyhow::bail!(AppError::CrlFfi { func: "ASN1_TIME_set" }); }
        if ffi::X509_REVOKED_set_revocationDate(rev, when_ptr) != 1 { ffi::ASN1_TIME_free(when_ptr); anyhow::bail!(AppError::CrlFfi { func: "X509_REVOKED_set_revocationDate" }); }
        if ffi::X509_CRL_add0_revoked(crl, rev) != 1 { anyhow::bail!(AppError::CrlFfi { func: "X509_CRL_add0_revoked" }); }
    }
    Ok(())
} }

#[inline]
pub(crate) unsafe fn sort_and_sign(crl: *mut ffi::X509_CRL, ca_key: &PKey<openssl::pkey::Private>) -> Result<()> { unsafe {
    if ffi::X509_CRL_sort(crl) != 1 { anyhow::bail!(AppError::CrlFfi { func: "X509_CRL_sort" }); }
    let md = ffi::EVP_sha256();
    if ffi::X509_CRL_sign(crl, ca_key.as_ptr(), md) == 0 { anyhow::bail!(AppError::CrlFfi { func: "X509_CRL_sign" }); }
    Ok(())
} }

#[inline]
pub(crate) unsafe fn encode_der_and_free(crl: *mut ffi::X509_CRL) -> Result<Vec<u8>> { unsafe {
    let mut buf: *mut u8 = std::ptr::null_mut();
    let len = ffi::i2d_X509_CRL(crl, &mut buf as *mut *mut u8);
    if len <= 0 || buf.is_null() { anyhow::bail!(AppError::CrlFfi { func: "i2d_X509_CRL" }); }
    let out = std::slice::from_raw_parts(buf as *const u8, len as usize).to_vec();
    ffi::OPENSSL_free(buf as *mut _);
    ffi::X509_CRL_free(crl);
    Ok(out)
} }

