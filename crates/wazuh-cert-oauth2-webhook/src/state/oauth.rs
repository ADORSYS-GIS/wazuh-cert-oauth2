use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use oauth2::basic::BasicClient;
use oauth2::{AuthType, AuthUrl, ClientId, ClientSecret, Scope, TokenResponse, TokenUrl};
use tokio::sync::RwLock;
use wazuh_cert_oauth2_model::models::document::DiscoveryDocument;

use super::ProxyState;

#[derive(Clone)]
pub(crate) struct OAuthConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub scope: Option<String>,
    pub audience: Option<String>,
}

#[derive(Clone)]
pub(crate) struct CachedToken {
    pub token: String,
    pub exp: Instant,
}

pub(crate) fn build_oauth(
    issuer: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    scope: Option<String>,
    audience: Option<String>,
) -> Option<OAuthConfig> {
    match (issuer, client_id, client_secret) {
        (Some(iss), Some(id), Some(sec)) => Some(OAuthConfig {
            issuer: iss,
            client_id: id,
            client_secret: sec,
            scope,
            audience,
        }),
        _ => None,
    }
}

pub(crate) async fn acquire_oauth_token(state: &ProxyState) -> Result<Option<String>> {
    let cfg = match &state.oauth {
        Some(c) => c.clone(),
        None => return Ok(None),
    };
    let disc_url = format!(
        "{}/.well-known/openid-configuration",
        cfg.issuer.trim_end_matches('/')
    );
    let doc: DiscoveryDocument = state.http.fetch_json(&disc_url).await?;

    if let Some(cached) = state.token_cache.read().await.clone()
        && Instant::now() < cached.exp
    {
        return Ok(Some(cached.token));
    }

    let mut basic_client = BasicClient::new(ClientId::new(cfg.client_id.clone()))
        .set_auth_uri(AuthUrl::new(doc.authorization_endpoint)?)
        .set_token_uri_option(Some(TokenUrl::new(doc.token_endpoint)?));
    basic_client = basic_client.set_client_secret(ClientSecret::new(cfg.client_secret.clone()));
    let client = basic_client.set_auth_type(AuthType::BasicAuth);

    let mut req = client.exchange_client_credentials()?;
    if let Some(s) = &cfg.scope {
        req = req.add_scope(Scope::new(s.clone()));
    }
    if let Some(aud) = &cfg.audience {
        req = req.add_extra_param("audience", aud.clone());
    }

    let token = req.request_async(state.http.client()).await?;
    let access = token.access_token().secret().to_string();
    cache_token(&state.token_cache, access.clone(), token.expires_in()).await;
    Ok(Some(access))
}

pub(crate) async fn cache_token(
    cache: &Arc<RwLock<Option<CachedToken>>>,
    token: String,
    ttl: Option<Duration>,
) {
    let now = Instant::now();
    let ttl = ttl.unwrap_or_else(|| Duration::from_secs(300));
    let skew = Duration::from_secs(30);
    let exp = now + ttl.saturating_sub(skew);
    let mut guard = cache.write().await;
    *guard = Some(CachedToken { token, exp });
}
