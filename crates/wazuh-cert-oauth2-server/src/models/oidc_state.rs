use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::sync::RwLock;

use wazuh_cert_oauth2_model::models::document::DiscoveryDocument;
use wazuh_cert_oauth2_model::services::http_client::HttpClient;

pub struct OidcState {
    pub(crate) audiences: Vec<String>,
    issuer: String,
    discovery_ttl: Duration,
    jwks_ttl: Duration,
    http: HttpClient,
    inner: RwLock<Inner>,
}

struct Inner {
    discovery: Option<(Arc<DiscoveryDocument>, Instant)>,
    jwks: Option<(Arc<jsonwebtoken::jwk::JwkSet>, Instant)>,
}

impl OidcState {
    pub fn new(
        issuer: String,
        audiences: Vec<String>,
        discovery_ttl: Duration,
        jwks_ttl: Duration,
        http: HttpClient,
    ) -> Self {
        Self {
            audiences,
            issuer,
            discovery_ttl,
            jwks_ttl,
            http,
            inner: RwLock::new(Inner {
                discovery: None,
                jwks: None,
            }),
        }
    }

    pub async fn get_discovery(&self) -> Result<Arc<DiscoveryDocument>> {
        let now = Instant::now();
        let mut inner = self.inner.write().await;
        // Check again after acquiring write lock
        if let Some((doc, fetched)) = &inner.discovery {
            if now.duration_since(*fetched) < self.discovery_ttl {
                return Ok(doc.clone());
            }
        }

        let url = format!("{}/.well-known/openid-configuration", self.issuer);
        let doc: DiscoveryDocument = self.http.fetch_json(&url).await?;
        let doc = Arc::new(doc);
        inner.discovery = Some((doc.clone(), Instant::now()));
        Ok(doc)
    }

    pub async fn get_jwks(&self) -> Result<Arc<jsonwebtoken::jwk::JwkSet>> {
        let now = Instant::now();
        let mut inner = self.inner.write().await;
        // Check again after acquiring write lock
        if let Some((jwks, fetched)) = &inner.jwks {
            if now.duration_since(*fetched) < self.jwks_ttl {
                return Ok(jwks.clone());
            }
        }

        let doc = match &inner.discovery {
            Some((d, fetched)) if now.duration_since(*fetched) < self.discovery_ttl => d.clone(),
            _ => {
                drop(inner);
                let doc = self.get_discovery().await?;
                inner = self.inner.write().await;
                doc
            }
        };

        let jwks: jsonwebtoken::jwk::JwkSet = self.http.fetch_json(&doc.jwks_uri).await?;
        let jwks = Arc::new(jwks);
        inner.jwks = Some((jwks.clone(), Instant::now()));
        Ok(jwks)
    }
}
