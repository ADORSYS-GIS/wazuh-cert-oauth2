use anyhow::Result;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::X509NameBuilder;
use openssl::x509::X509ReqBuilder;

/// Generate an RSA-2048 keypair and a PKCS#10 CSR with CN set to `sub`.
/// Returns (csr_pem, private_key_pem)
pub fn generate_key_and_csr(sub: &str) -> Result<(String, String)> {
    let rsa = Rsa::generate(2048)?;
    let pkey = PKey::from_rsa(rsa)?;

    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_nid(Nid::COMMONNAME, sub)?;
    let name = name_builder.build();

    let mut req_builder = X509ReqBuilder::new()?;
    req_builder.set_pubkey(&pkey)?;
    req_builder.set_subject_name(&name)?;
    req_builder.sign(&pkey, MessageDigest::sha256())?;
    let csr = req_builder.build();

    let csr_pem = String::from_utf8(csr.to_pem()?)?;
    let key_pem = String::from_utf8(pkey.private_key_to_pem_pkcs8()?)?;

    Ok((csr_pem, key_pem))
}

