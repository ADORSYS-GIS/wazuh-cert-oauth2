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
