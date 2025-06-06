use anyhow::Result;
use oauth2::basic::BasicClient;
use oauth2::{
    AuthType, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    RedirectUrl, TokenResponse, TokenUrl,
};
use reqwest::ClientBuilder;
use wazuh_cert_oauth2_model::models::document::DiscoveryDocument;

#[derive(Debug)]
pub struct GetTokenParams {
    pub document: DiscoveryDocument,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub is_service_account: bool,
}

/// Get a token from the OAuth2 server.
pub async fn get_token(params: GetTokenParams) -> Result<String> {
    let http_client = ClientBuilder::new()
        .build()?;
    
    let mut basic_client = BasicClient::new(ClientId::new(params.client_id.to_string()))
        .set_auth_uri(AuthUrl::new(params.document.authorization_endpoint)?)
        .set_token_uri_option(Some(TokenUrl::new(params.document.token_endpoint)?));

    if let Some(secret) = params.client_secret.map(ClientSecret::new) {
        basic_client = basic_client.set_client_secret(secret)
    }

    // Create an OAuth2 client by specifying the client ID, client secret, authorization URL and token URL.
    let client = if params.is_service_account {
        basic_client.set_auth_type(AuthType::BasicAuth)
    } else {
        basic_client.set_redirect_uri(RedirectUrl::new("urn:ietf:wg:oauth:2.0:oob".to_string())?)
    };

    if params.is_service_account {
        let token_result = client
            .exchange_client_credentials()?
            .request_async(&http_client)
            .await?;

        info!("Token received!");
        return Ok(token_result.access_token().secret().clone());
    }
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
        .exchange_code(code)?
        .set_pkce_verifier(pkce_verifier)
        .request_async(&http_client)
        .await?;

    info!("Token received!");

    Ok(token_result.access_token().secret().clone())
}
