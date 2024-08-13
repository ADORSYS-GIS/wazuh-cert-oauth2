use std::env::var;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::Result;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::{X509, X509Req};
use openssl::x509::extension::BasicConstraints;
use openssl::x509::X509NameBuilder;
use openssl::x509::X509ReqBuilder;

use crate::models::register_agent_dto::{RegisterAgentDto, UserKey};

pub fn gen_cert(dto: RegisterAgentDto) -> Result<UserKey> {
    // Load the CA certificate and private key
    let root_ca = read_file(var("ROOT_CA_PATH")?)?;
    let root_ca_key = read_file(var("ROOT_CA_KEY_PATH")?)?;
    let ca_cert = X509::from_pem(&root_ca)?;
    let ca_key = PKey::private_key_from_pem(&root_ca_key)?;

    // Generate a new private key for the agent
    let agent_key = Rsa::generate(2048)?;
    let agent_pkey = PKey::from_rsa(agent_key)?;

    // Create a CSR for the agent
    let mut req_builder = X509ReqBuilder::new()?;
    req_builder.set_pubkey(&agent_pkey)?;

    // Set the subject name for the CSR
    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_text("CN", &dto.name)?;
    let name = name_builder.build();
    req_builder.set_subject_name(&name)?;
    req_builder.sign(&agent_pkey, openssl::hash::MessageDigest::sha256())?;
    let csr = req_builder.build();

    // Create the agent certificate by signing the CSR with the CA key
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

// Utility function to read a file into a Vec<u8>
fn read_file<P: AsRef<Path>>(path: P) -> Result<Vec<u8>, std::io::Error> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    Ok(buffer)
}

// Sign the CSR with the CA to create a certificate
fn sign_csr_with_ca(csr: &X509Req, ca_cert: &X509, ca_key: &PKey<openssl::pkey::Private>) -> Result<X509> {
    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    builder.set_subject_name(csr.subject_name())?;
    let pkey = csr.public_key()?;
    builder.set_pubkey(&pkey)?;
    builder.set_issuer_name(ca_cert.subject_name())?;

    // Set certificate extensions, like basic constraints
    let basic_constraints = BasicConstraints::new().critical().ca().build()?;
    builder.append_extension(basic_constraints)?;

    builder.sign(ca_key, openssl::hash::MessageDigest::sha256())?;

    Ok(builder.build())
}