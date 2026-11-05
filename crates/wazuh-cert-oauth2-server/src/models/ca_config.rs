use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::fs::read;

use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::x509::X509;
use tokio::sync::RwLock;
use wazuh_cert_oauth2_model::models::errors::AppResult;

pub struct CaProvider {
    root_ca_path: String,
    root_ca_key_path: String,
    ttl: Duration,
    crl_dist_url: Option<String>,
    inner: RwLock<Inner>,
}

struct Inner {
    ca_cert: Option<(Arc<X509>, Instant)>,
    ca_key: Option<(Arc<PKey<Private>>, Instant)>,
}

impl CaProvider {
    pub fn new(
        root_ca_path: String,
        root_ca_key_path: String,
        ttl: Duration,
        crl_dist_url: Option<String>,
    ) -> Self {
        Self {
            root_ca_path,
            root_ca_key_path,
            ttl,
            crl_dist_url,
            inner: RwLock::new(Inner {
                ca_cert: None,
                ca_key: None,
            }),
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn get(&self) -> AppResult<(Arc<X509>, Arc<PKey<Private>>)> {
        let now = Instant::now();

        let mut inner = self.inner.write().await;
        if let (Some((cert, c_ts)), Some((key, k_ts))) = (&inner.ca_cert, &inner.ca_key)
            && now.duration_since(*c_ts) < self.ttl
            && now.duration_since(*k_ts) < self.ttl
        {
            return Ok((cert.clone(), key.clone()));
        }

        // Refresh from disk
        let cert_pem = read(&self.root_ca_path).await?;
        let key_pem = read(&self.root_ca_key_path).await?;
        let cert = Arc::new(X509::from_pem(&cert_pem)?);
        let key = Arc::new(PKey::private_key_from_pem(&key_pem)?);
        inner.ca_cert = Some((cert.clone(), Instant::now()));
        inner.ca_key = Some((key.clone(), Instant::now()));
        Ok((cert, key))
    }

    pub fn crl_dist_url(&self) -> Option<&str> {
        self.crl_dist_url.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::CaProvider;
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::{X509, X509NameBuilder};
    use std::sync::Arc;
    use std::time::Duration;

    fn write_ca_files() -> (std::path::PathBuf, std::path::PathBuf) {
        let rsa = Rsa::generate(2048).expect("rsa generation");
        let key = PKey::from_rsa(rsa).expect("pkey conversion");
        let mut name_builder = X509NameBuilder::new().expect("name builder");
        name_builder
            .append_entry_by_nid(Nid::COMMONNAME, "test-ca")
            .expect("append cn");
        let name = name_builder.build();
        let mut builder = X509::builder().expect("x509 builder");
        builder.set_version(2).expect("set version");
        builder.set_subject_name(&name).expect("set subject");
        builder.set_issuer_name(&name).expect("set issuer");
        builder.set_pubkey(&key).expect("set pubkey");
        builder
            .set_not_before(Asn1Time::days_from_now(0).unwrap().as_ref())
            .expect("set not_before");
        builder
            .set_not_after(Asn1Time::days_from_now(365).unwrap().as_ref())
            .expect("set not_after");
        builder.sign(&key, MessageDigest::sha256()).expect("sign");

        let cert_pem = builder.build().to_pem().expect("cert pem");
        let key_pem = key.private_key_to_pem_pkcs8().expect("key pem");

        let dir = std::env::temp_dir().join(format!("ca-config-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create dir");
        let cert_path = dir.join("ca.pem");
        let key_path = dir.join("ca.key");
        std::fs::write(&cert_path, cert_pem).expect("write cert");
        std::fs::write(&key_path, key_pem).expect("write key");
        (cert_path, key_path)
    }

    #[tokio::test]
    async fn get_loads_ca_from_disk_and_caches() {
        let (cert_path, key_path) = write_ca_files();
        let provider = CaProvider::new(
            cert_path.to_string_lossy().to_string(),
            key_path.to_string_lossy().to_string(),
            Duration::from_secs(60),
            Some("https://crl.example/crl.pem".to_string()),
        );

        let (cert, key) = provider.get().await.expect("ca should load");
        assert!(cert.to_pem().is_ok());
        assert!(key.private_key_to_pem_pkcs8().is_ok());
        assert_eq!(provider.crl_dist_url(), Some("https://crl.example/crl.pem"));

        // Second call within TTL should return the cached values.
        let (cert2, key2) = provider.get().await.expect("cached ca");
        assert!(std::ptr::eq(Arc::as_ptr(&cert), Arc::as_ptr(&cert2)));
        assert!(std::ptr::eq(Arc::as_ptr(&key), Arc::as_ptr(&key2)));

        std::fs::remove_file(&cert_path).ok();
        std::fs::remove_file(&key_path).ok();
    }
}
