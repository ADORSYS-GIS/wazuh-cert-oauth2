use oauth2::basic::BasicClient;
use oauth2::{
    AuthType, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    RedirectUrl, TokenResponse, TokenUrl,
};
use std::process::Command;
use wazuh_cert_oauth2_model::models::document::DiscoveryDocument;
use wazuh_cert_oauth2_model::models::errors::AppResult;
use wazuh_cert_oauth2_model::services::http_client::HttpClient;

#[derive(Debug)]
/// Parameters to request an OAuth2 access token.
pub struct GetTokenParams {
    pub document: DiscoveryDocument,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub is_service_account: bool,
}

/// Get a token from the OAuth2 server.
pub async fn get_token(http: &HttpClient, params: GetTokenParams) -> AppResult<String> {
    let mut basic_client = BasicClient::new(ClientId::new(params.client_id.to_string()))
        .set_auth_uri(AuthUrl::new(params.document.authorization_endpoint)?)
        .set_token_uri_option(Some(TokenUrl::new(params.document.token_endpoint)?));
    if let Some(secret) = params.client_secret.map(ClientSecret::new) {
        basic_client = basic_client.set_client_secret(secret)
    }

    let client = if params.is_service_account {
        basic_client.set_auth_type(AuthType::BasicAuth)
    } else {
        basic_client.set_redirect_uri(RedirectUrl::new("urn:ietf:wg:oauth:2.0:oob".to_string())?)
    };

    if params.is_service_account {
        let token_result = client
            .exchange_client_credentials()?
            .request_async(http.client())
            .await?;
        info!("Token received!");
        return Ok(token_result.access_token().secret().clone());
    }

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (auth_url, _csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .set_pkce_challenge(pkce_challenge)
        .url();
    let auth_url_string = auth_url.to_string();
    // Try to open the URL in the default browser, but always print it as fallback.
    if !open_in_browser(&auth_url_string) {
        info!(
            "Please open this URL in your browser: {}\n",
            auth_url_string
        );
    } else {
        info!("Opened your default browser to: {}\n", auth_url_string);
    }

    let mut auth_code = String::new();
    std::io::stdin().read_line(&mut auth_code)?;
    let code = AuthorizationCode::new(auth_code.trim().to_string());
    info!("Exchanging code for token...");
    let token_result = client
        .exchange_code(code)?
        .set_pkce_verifier(pkce_verifier)
        .request_async(http.client())
        .await?;
    Ok(token_result.access_token().secret().clone())
}

/// Attempt to open a URL in the user's default browser.
/// Returns true on success, false if launching failed.
fn open_in_browser(url: &str) -> bool {
    // Windows: use `start` via cmd.exe. The empty string is a window title placeholder.
    #[cfg(target_os = "windows")]
    {
        if Command::new("rundll32")
            .arg("url.dll,FileProtocolHandler")
            .arg(url)
            .spawn()
            .map(|_| true)
            .unwrap_or(false)
        {
            return true;
        }
    }

    // macOS: use `open`.
    #[cfg(target_os = "macos")]
    {
        return Command::new("open")
            .arg(url)
            .spawn()
            .map(|_| true)
            .unwrap_or(false);
    }

    // Linux and other Unix: prefer `xdg-open`.
    #[cfg(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    {
        // Try xdg-open; if unavailable, fall back to printing.
        return Command::new("xdg-open")
            .arg(url)
            .spawn()
            .map(|_| true)
            .unwrap_or(false);
    }

    // Fallback for any other targets: do nothing.
    #[allow(unreachable_code)]
    false
}
