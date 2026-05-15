use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::X509NameBuilder;
use openssl::x509::X509ReqBuilder;
use wazuh_cert_oauth2_model::models::errors::AppResult;

/// Generate an RSA-2048 keypair and a PKCS#10 CSR with CN set to `sub`.
/// Returns (csr_pem, private_key_pem)
pub fn generate_key_and_csr(sub: &str) -> AppResult<(String, String)> {
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

#[cfg(test)]
mod tests {
    use super::generate_key_and_csr;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::x509::X509Req;

    #[test]
    fn generated_csr_has_subject_cn_and_matches_private_key() {
        let subject = "agent-subject-123";
        let (csr_pem, key_pem) = generate_key_and_csr(subject).expect("csr generation should work");

        let csr = X509Req::from_pem(csr_pem.as_bytes()).expect("csr pem should parse");
        let key = PKey::private_key_from_pem(key_pem.as_bytes()).expect("key pem should parse");

        assert!(csr.verify(&key).expect("csr verification should run"));
        assert_eq!(key.rsa().expect("rsa key").size() * 8, 2048);

        let cn = csr
            .subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .expect("common name should exist")
            .data()
            .as_utf8()
            .expect("cn should be utf8")
            .to_string();
        assert_eq!(cn, subject);
    }
}
