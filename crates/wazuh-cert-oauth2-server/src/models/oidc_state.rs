use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

use wazuh_cert_oauth2_model::models::document::DiscoveryDocument;
use wazuh_cert_oauth2_model::models::errors::AppResult;
use wazuh_cert_oauth2_model::services::http_client::HttpClient;

pub struct OidcState {
    pub(crate) audiences: Option<Vec<String>>,
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
        audiences: Option<Vec<String>>,
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

    #[tracing::instrument(skip(self))]
    pub async fn get_discovery(&self) -> AppResult<Arc<DiscoveryDocument>> {
        let now = Instant::now();
        let mut inner = self.inner.write().await;
        // Check again after acquiring write lock
        if let Some((doc, fetched)) = &inner.discovery
            && now.duration_since(*fetched) < self.discovery_ttl
        {
            return Ok(doc.clone());
        }

        let url = format!("{}/.well-known/openid-configuration", self.issuer);
        let doc: DiscoveryDocument = self.http.fetch_json(&url).await?;
        let doc = Arc::new(doc);
        inner.discovery = Some((doc.clone(), Instant::now()));
        Ok(doc)
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_jwks(&self) -> AppResult<Arc<jsonwebtoken::jwk::JwkSet>> {
        let now = Instant::now();
        let mut inner = self.inner.write().await;
        // Check again after acquiring write lock
        if let Some((jwks, fetched)) = &inner.jwks
            && now.duration_since(*fetched) < self.jwks_ttl
        {
            return Ok(jwks.clone());
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

#[cfg(test)]
mod tests {
    use super::OidcState;
    use std::time::Duration;
    use wazuh_cert_oauth2_model::services::http_client::HttpClient;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn get_discovery_fetches_and_caches_document() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": server.uri(),
                "authorization_endpoint": format!("{}/auth", server.uri()),
                "token_endpoint": format!("{}/token", server.uri()),
                "jwks_uri": format!("{}/jwks", server.uri())
            })))
            .mount(&server)
            .await;

        let state = OidcState::new(
            server.uri(),
            Some(vec!["aud".to_string()]),
            Duration::from_secs(60),
            Duration::from_secs(60),
            HttpClient::new_with_defaults().expect("http client"),
        );

        let doc = state.get_discovery().await.expect("discovery should load");
        assert_eq!(doc.issuer, server.uri());
        // Second call should hit the cache.
        let doc2 = state.get_discovery().await.expect("cached discovery");
        assert!(std::sync::Arc::ptr_eq(&doc, &doc2));
    }

    #[tokio::test]
    async fn get_jwks_fetches_from_discovery_jwks_uri() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": server.uri(),
                "authorization_endpoint": format!("{}/auth", server.uri()),
                "token_endpoint": format!("{}/token", server.uri()),
                "jwks_uri": format!("{}/jwks", server.uri())
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": []
            })))
            .mount(&server)
            .await;

        let state = OidcState::new(
            server.uri(),
            None,
            Duration::from_secs(60),
            Duration::from_secs(60),
            HttpClient::new_with_defaults().expect("http client"),
        );

        let jwks = state.get_jwks().await.expect("jwks should load");
        assert!(jwks.keys.is_empty());
    }
}
