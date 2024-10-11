use std::env::var;
use std::fs::read;

use anyhow::Result;
use openssl::asn1::Asn1Time;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::{X509, X509Req};
use openssl::x509::extension::BasicConstraints;
use openssl::x509::X509NameBuilder;
use openssl::x509::X509ReqBuilder;
use rand::RngCore;
use rand::rngs::OsRng;

use wazuh_cert_oauth2_model::models::register_agent_dto::RegisterAgentDto;
use wazuh_cert_oauth2_model::models::user_key::UserKey;

use crate::handlers::middle::JwtToken;

/// Generate a certificate for the agent
pub fn gen_cert(_dto: RegisterAgentDto, JwtToken { claims }: JwtToken) -> Result<UserKey> {
    // Generate a 4096-bit RSA private key
    let rsa = Rsa::generate(4096)?;
    let agent_pkey = PKey::from_rsa(rsa)?;

    // Create a new CSR (Certificate Signing Request)
    let mut req_builder = X509ReqBuilder::new()?;
    req_builder.set_pubkey(&agent_pkey)?;

    // Set the subject name for the CSR
    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_text("CN", &claims.sub)?;
    // name_builder.append_entry_by_text("tokenAudience", &claims.aud)?;
    let name = name_builder.build();
    req_builder.set_subject_name(&name)?;
    req_builder.sign(&agent_pkey, openssl::hash::MessageDigest::sha256())?;
    let csr = req_builder.build();

    // Convert the CSR to PEM format
    // let _csr_pem = csr.to_pem()?;

    // Load the CA certificate and key
    let ca_cert_pem = read(var("ROOT_CA_PATH")?)?;
    let ca_key_pem = read(var("ROOT_CA_KEY_PATH")?)?;
    let ca_cert = X509::from_pem(&ca_cert_pem)?;
    let ca_key = PKey::private_key_from_pem(&ca_key_pem)?;

    // Sign the CSR with the CA to create the agent certificate
    let agent_cert = sign_csr_with_ca(&csr, &ca_cert, &ca_key)?;

    // Convert the private key and certificate to PEM format
    let private_key_pem = agent_pkey.private_key_to_pem_pkcs8()?;
    let cert_pem = agent_cert.to_pem()?;

    // Return the keys and certificate as a JSON response
    Ok(UserKey {
        public_key: String::from_utf8(cert_pem)?,
        private_key: String::from_utf8(private_key_pem)?,
    })
}

/// Sign the CSR with the CA to create a certificate
fn sign_csr_with_ca(
    csr: &X509Req,
    ca_cert: &X509,
    ca_key: &PKey<openssl::pkey::Private>,
) -> Result<X509> {
    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    builder.set_subject_name(csr.subject_name())?;
    let pkey = csr.public_key()?;
    builder.set_pubkey(&pkey)?;
    builder.set_issuer_name(ca_cert.subject_name())?;

    // Set certificate serial number
    let mut serial = [0u8; 16];
    OsRng.fill_bytes(&mut serial);
    let serial_number = openssl::bn::BigNum::from_slice(&serial)?.to_asn1_integer()?;
    builder.set_serial_number(&serial_number)?;

    // Set certificate validity period
    builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
    builder.set_not_after(Asn1Time::days_from_now(365)?.as_ref())?;

    // Set basic constraints (Not a CA certificate)
    let basic_constraints = BasicConstraints::new().build()?;
    builder.append_extension(basic_constraints)?;

    // Sign the certificate with the CA's private key
    builder.sign(ca_key, openssl::hash::MessageDigest::sha256())?;

    Ok(builder.build())
}