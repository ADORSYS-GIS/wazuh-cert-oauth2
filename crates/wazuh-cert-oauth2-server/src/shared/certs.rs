use std::env::var;
use std::fs::read;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::Id as PKeyId;
use openssl::pkey::PKey;
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectKeyIdentifier,
};
use openssl::x509::{X509NameBuilder, X509Ref, X509Req, X509};
use rand::RngCore;
use rand::rngs::OsRng;

use wazuh_cert_oauth2_model::models::sign_csr_request::SignCsrRequest;
use wazuh_cert_oauth2_model::models::signed_cert_response::SignedCertResponse;

use crate::handlers::middle::JwtToken;

/// Sign a client-provided CSR with the issuing CA; never generate or return private keys
pub fn sign_csr(dto: SignCsrRequest, JwtToken { claims }: JwtToken) -> Result<SignedCertResponse> {
    let csr = X509Req::from_pem(dto.csr_pem.as_bytes())?;

    // Verify CSR signature
    let csr_pubkey = csr.public_key().context("CSR missing public key")?;
    let verified = csr.verify(&csr_pubkey)?;
    if !verified {
        bail!("CSR verification failed");
    }

    // Enforce key policy (RSA-2048/3072 or ECDSA-P-256)
    enforce_key_policy(&csr_pubkey)?;

    // Load the CA certificate and key
    let ca_cert_pem = read(var("ROOT_CA_PATH")?)?;
    let ca_key_pem = read(var("ROOT_CA_KEY_PATH")?)?;
    let ca_cert = X509::from_pem(&ca_cert_pem)?;
    let ca_key = PKey::private_key_from_pem(&ca_key_pem)?;

    // Build certificate using CSR public key, but enforce subject from OAuth2 claims
    let cert = sign_csr_with_ca(&csr, &ca_cert, &ca_key, &claims.sub)?;

    Ok(SignedCertResponse {
        certificate_pem: String::from_utf8(cert.to_pem()?)?,
        ca_cert_pem: String::from_utf8(ca_cert_pem)?,
    })
}

fn set_subject_cn(name_builder: &mut X509NameBuilder, cn: &str) -> Result<()> {
    // Set Common Name to the subject identifier from claims
    name_builder.append_entry_by_nid(Nid::COMMONNAME, cn)?;
    Ok(())
}

/// Sign the CSR with the CA to create a certificate, enforcing EKU/KU/SKI and subject
fn sign_csr_with_ca(
    csr: &X509Req,
    ca_cert: &X509Ref,
    ca_key: &PKey<openssl::pkey::Private>,
    subject_cn: &str,
) -> Result<X509> {
    let mut builder = X509::builder()?;
    builder.set_version(2)?;

    // Subject from OAuth claims (ignore CSR subject)
    let mut name_builder = X509NameBuilder::new()?;
    set_subject_cn(&mut name_builder, subject_cn)?;
    let subject_name = name_builder.build();
    builder.set_subject_name(&subject_name)?;

    // Public key from CSR
    let pkey = csr.public_key()?;
    builder.set_pubkey(&pkey)?;
    builder.set_issuer_name(ca_cert.subject_name())?;

    // Serial number
    let mut serial = [0u8; 16];
    OsRng.try_fill_bytes(&mut serial)?;
    // Ensure positive serial (clear MSB) and non-zero
    serial[0] &= 0x7F;
    if serial.iter().all(|&b| b == 0) {
        serial[0] = 1;
    }
    let serial_number = openssl::bn::BigNum::from_slice(&serial)?.to_asn1_integer()?;
    builder.set_serial_number(&serial_number)?;

    // Validity with small clock skew allowance (-5 minutes)
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs() as i64;
    let not_before = Asn1Time::from_unix(now - 300)?; // 5 minutes ago
    builder.set_not_before(not_before.as_ref())?;
    builder.set_not_after(Asn1Time::days_from_now(365)?.as_ref())?;

    // Basic Constraints: End-entity cert (not a CA)
    let basic_constraints = BasicConstraints::new().critical().build()?;
    builder.append_extension(basic_constraints)?;

    // Subject Key Identifier
    let ski = SubjectKeyIdentifier::new().build(&builder.x509v3_context(Some(ca_cert), None))?;
    builder.append_extension(ski)?;

    // Authority Key Identifier
    let aki = AuthorityKeyIdentifier::new()
        .keyid(true)
        .issuer(true)
        .build(&builder.x509v3_context(Some(ca_cert), None))?;
    builder.append_extension(aki)?;

    // Key Usage
    let is_rsa = matches!(pkey.id(), PKeyId::RSA);
    let mut ku = KeyUsage::new();
    ku.critical();
    ku.digital_signature();
    if is_rsa {
        ku.key_encipherment();
    }
    builder.append_extension(ku.build()?)?;

    // Extended Key Usage: clientAuth
    let eku = ExtendedKeyUsage::new().client_auth().build()?;
    builder.append_extension(eku)?;

    // Optional: put subjectAltName with CN as DNS-like if desired; here omit unless needed
    // If you want SAN copy, uncomment and adapt:
    // let san = SubjectAlternativeName::new().dns(subject_cn).build(&context)?;
    // builder.append_extension(san)?;

    // Sign
    builder.sign(ca_key, MessageDigest::sha256())?;

    Ok(builder.build())
}

fn enforce_key_policy(pkey: &PKey<openssl::pkey::Public>) -> Result<()> {
    match pkey.id() {
        PKeyId::RSA => {
            let rsa = pkey.rsa()?;
            let bits = (rsa.size() as usize) * 8; // size in bytes -> bits
            if bits < 2048 {
                bail!("RSA key too small: {} bits (min 2048)", bits);
            }
        }
        PKeyId::EC => {
            let ec = pkey.ec_key()?;
            let nid = ec
                .group()
                .curve_name()
                .ok_or_else(|| anyhow::anyhow!("Unknown EC curve"))?;
            if nid != Nid::X9_62_PRIME256V1 {
                bail!("Unsupported EC curve: {:?} (only P-256 allowed)", nid);
            }
        }
        other => {
            bail!("Unsupported key type: {:?}", other);
        }
    }
    Ok(())
}
