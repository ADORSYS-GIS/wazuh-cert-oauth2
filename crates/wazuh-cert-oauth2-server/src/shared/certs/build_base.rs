use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::Id as PKeyId;
use openssl::pkey::PKey;
use openssl::x509::{X509NameBuilder, X509Ref, X509Req};
use rand::TryRng;
use rand::rngs::SysRng;
use wazuh_cert_oauth2_model::models::errors::AppResult;

pub(crate) fn set_subject_cn(name_builder: &mut X509NameBuilder, cn: &str) -> AppResult<()> {
    name_builder.append_entry_by_nid(Nid::COMMONNAME, cn)?;
    Ok(())
}

pub(crate) fn set_subject_and_pubkey(
    builder: &mut openssl::x509::X509Builder,
    csr: &X509Req,
    ca_cert: &X509Ref,
    subject_cn: &str,
) -> AppResult<bool> {
    let mut name_builder = X509NameBuilder::new()?;
    set_subject_cn(&mut name_builder, subject_cn)?;
    let subject_name = name_builder.build();
    builder.set_subject_name(&subject_name)?;
    let pkey = csr.public_key()?;
    builder.set_pubkey(&pkey)?;
    builder.set_issuer_name(ca_cert.subject_name())?;
    Ok(matches!(pkey.id(), PKeyId::RSA))
}

pub(crate) fn set_serial_number(builder: &mut openssl::x509::X509Builder) -> AppResult<()> {
    let mut serial = [0u8; 16];
    SysRng.try_fill_bytes(&mut serial)?;
    serial[0] &= 0x7F;
    if serial.iter().all(|&b| b == 0) {
        serial[0] = 1;
    }
    let serial_number = openssl::bn::BigNum::from_slice(&serial)?.to_asn1_integer()?;
    builder.set_serial_number(&serial_number)?;
    Ok(())
}

pub(crate) fn set_validity_1y(builder: &mut openssl::x509::X509Builder) -> AppResult<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs() as i64;
    let not_before = Asn1Time::from_unix(now - 300)?;
    builder.set_not_before(not_before.as_ref())?;
    builder.set_not_after(Asn1Time::days_from_now(365)?.as_ref())?;
    Ok(())
}

pub(crate) fn sign_builder(
    builder: &mut openssl::x509::X509Builder,
    ca_key: &PKey<openssl::pkey::Private>,
) -> AppResult<()> {
    builder.sign(ca_key, MessageDigest::sha256())?;
    Ok(())
}
