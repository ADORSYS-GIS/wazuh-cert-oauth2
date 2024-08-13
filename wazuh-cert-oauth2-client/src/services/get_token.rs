use anyhow::Result;
use oauth2::{AuthorizationCode, AuthUrl, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl, TokenResponse, TokenUrl};
use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;

use wazuh_cert_oauth2_model::models::document::DiscoveryDocument;
use wazuh_cert_oauth2_model::services::fetch_only::fetch_only;

pub async fn get_token(issuer: &str, client_id: &str, client_secret: Option<String>) -> Result<String> {
    let document = fetch_only::<DiscoveryDocument>(&format!("{}/.well-known/openid-configuration", issuer)).await?;

    let client = BasicClient::new(
        ClientId::new(client_id.to_string()),
        client_secret.map(ClientSecret::new),
        AuthUrl::new(document.authorization_endpoint)?,
        Some(TokenUrl::new(document.token_endpoint)?),
    ).set_redirect_uri(RedirectUrl::new("urn:ietf:wg:oauth:2.0:oob".to_string())?);

    // Generate a PKCE challenge.
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // User needs to go to the authorization URL manually
    let (auth_url, _csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .set_pkce_challenge(pkce_challenge)
        .url();

    info!("Please open this URL in your browser: {}\n", auth_url);

    let mut auth_code = String::new();
    std::io::stdin().read_line(&mut auth_code)?;
    let code = AuthorizationCode::new(auth_code.trim().to_string());

    info!("Exchanging code for token...");

    let token_result = client
        .exchange_code(code)
        .set_pkce_verifier(pkce_verifier)
        .request_async(async_http_client)
        .await?;

    info!("Token received!");

    Ok(token_result.access_token().secret().clone())
}
