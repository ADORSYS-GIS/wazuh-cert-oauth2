use oauth2::basic::BasicClient;
use oauth2::{
    AuthType, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    RedirectUrl, TokenResponse, TokenUrl,
};
use std::process::Command;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use url::Url;
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
    pub timeout_secs: u64,
}

/// Get a token from the OAuth2 server.
pub async fn get_token(http: &HttpClient, params: GetTokenParams) -> AppResult<String> {
    let mut basic_client = BasicClient::new(ClientId::new(params.client_id.to_string()))
        .set_auth_uri(AuthUrl::new(params.document.authorization_endpoint)?)
        .set_token_uri_option(Some(TokenUrl::new(params.document.token_endpoint)?));
    if let Some(secret) = params.client_secret.map(ClientSecret::new) {
        basic_client = basic_client.set_client_secret(secret)
    }

    if params.is_service_account {
        let token_result = basic_client
            .set_auth_type(AuthType::BasicAuth)
            .exchange_client_credentials()?
            .request_async(http.client())
            .await?;
        info!("Token received!");
        return Ok(token_result.access_token().secret().clone());
    }

    // Bind the listener directly to avoid race conditions
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    debug!("Local callback server listening on port {}", port);

    let client = basic_client.set_redirect_uri(RedirectUrl::new(format!(
        "http://localhost:{}/callback",
        port
    ))?);

    // Generate PKCE pair
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate authorization URL with PKCE and CSRF
    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .set_pkce_challenge(pkce_challenge)
        .url();

    // Create a channel to receive the auth code
    let (tx, rx) = oneshot::channel::<String>();

    let csrf_secret = csrf_token.secret().clone();
    let server_handle = tokio::spawn(async move {
        let mut tx = Some(tx);
        while let Ok((mut stream, _)) = listener.accept().await {
            // Buffer size increased to 4096 bytes
            let mut buffer = [0; 4096];
            match stream.read(&mut buffer).await {
                Ok(n) if n > 0 => {
                    let request = String::from_utf8_lossy(&buffer[..n]);
                    let (code, state_valid) = parse_callback_request(&request, &csrf_secret);

                    let (response, success) = if state_valid {
                        if let Some(auth_code) = code {
                            // Send code only if it's the first connection that provides it
                            if let Some(tx) = tx.take() {
                                let _ = tx.send(auth_code);
                            }
                            (
                                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<h2>Auth complete - you can close this tab.</h2>",
                                true,
                            )
                        } else {
                            (
                                "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<h2>Auth failed: Missing code parameter.</h2>",
                                false,
                            )
                        }
                    } else {
                        (
                            "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<h2>Auth failed: CSRF token mismatch or missing state.</h2>",
                            false,
                        )
                    };

                    let _ = stream.write_all(response.as_bytes()).await;
                    if success {
                        // Successfully received code, exit server loop
                        break;
                    }
                }
                Ok(_) => {
                    debug!("Connection closed by client before data was sent.");
                }
                Err(e) => {
                    error!("Error reading from TCP stream: {}", e);
                }
            }
        }
    });

    let auth_url_string = auth_url.to_string();
    if !open_in_browser(&auth_url_string) {
        info!(
            "Please open this URL in your browser: {}\n",
            auth_url_string
        );
    } else {
        info!("Opened your default browser to: {}\n", auth_url_string);
    }

    // Configurable timeout (default 120s)
    let timeout = params.timeout_secs;
    let auth_code = match tokio::time::timeout(tokio::time::Duration::from_secs(timeout), rx).await
    {
        Ok(Ok(code)) => code,
        Ok(Err(_)) => return Err(anyhow::anyhow!("Failed to receive authorization code").into()),
        Err(_) => return Err(anyhow::anyhow!("Timeout waiting for authorization code").into()),
    };

    server_handle.abort();

    info!("Exchanging code for token...");
    let token_result = client
        .exchange_code(AuthorizationCode::new(auth_code))?
        .set_pkce_verifier(pkce_verifier)
        .request_async(http.client())
        .await?;
    Ok(token_result.access_token().secret().clone())
}

/// Parses the callback request to extract the code and validate the state.
fn parse_callback_request(request: &str, expected_csrf_token: &str) -> (Option<String>, bool) {
    let mut lines = request.lines();
    let first_line = lines.next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let _method = parts.next();
    let path = parts.next().unwrap_or("");

    let mut code = None;
    let mut state_valid = false;

    // Robust HTTP parsing using 'url' crate
    if let Ok(url) = Url::parse(&format!("http://localhost{}", path)) {
        for (k, v) in url.query_pairs() {
            if k == "code" {
                code = Some(v.into_owned());
            } else if k == "state" && v == expected_csrf_token {
                state_valid = true;
            }
        }
    }
    (code, state_valid)
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
        use std::env;
        if let Ok(user) = env::var("SUDO_USER") {
            let mut cmd = Command::new("runuser");
            cmd.arg("-u").arg(&user).arg("--").arg("xdg-open").arg(url);

            // Forward display and dbus session so xdg-open works cleanly
            if let Ok(display) = env::var("DISPLAY") {
                cmd.env("DISPLAY", display);
            }
            if let Ok(wayland) = env::var("WAYLAND_DISPLAY") {
                cmd.env("WAYLAND_DISPLAY", wayland);
            }
            if let Ok(dbus) = env::var("DBUS_SESSION_BUS_ADDRESS") {
                cmd.env("DBUS_SESSION_BUS_ADDRESS", dbus);
            }

            // Suppress GTK noise when using firefox as the default browser, which is common on Linux.
            cmd.stderr(std::fs::File::open("/dev/null").unwrap());

            return cmd.spawn().map(|_| true).unwrap_or(false);
        }
    }

    // Fallback for any other targets: do nothing.
    #[allow(unreachable_code)]
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_callback_request_success() {
        let request =
            "GET /callback?code=some_code&state=expected_state HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let expected_csrf = "expected_state";
        let (code, state_valid) = parse_callback_request(request, expected_csrf);
        assert_eq!(code, Some("some_code".to_string()));
        assert!(state_valid);
    }

    #[test]
    fn test_parse_callback_request_csrf_mismatch() {
        let request =
            "GET /callback?code=some_code&state=wrong_state HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let expected_csrf = "expected_state";
        let (code, state_valid) = parse_callback_request(request, expected_csrf);
        assert_eq!(code, Some("some_code".to_string()));
        assert!(!state_valid);
    }

    #[test]
    fn test_parse_callback_request_missing_code() {
        let request = "GET /callback?state=expected_state HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let expected_csrf = "expected_state";
        let (code, state_valid) = parse_callback_request(request, expected_csrf);
        assert_eq!(code, None);
        assert!(state_valid);
    }

    #[test]
    fn test_parse_callback_request_malformed() {
        let request = "not an http request";
        let expected_csrf = "state";
        let (code, state_valid) = parse_callback_request(request, expected_csrf);
        assert_eq!(code, None);
        assert!(!state_valid);
    }

    #[test]
    fn test_parse_callback_request_with_fragment() {
        let request = "GET /callback?code=some_code&state=expected_state#fragment HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let expected_csrf = "expected_state";
        let (code, state_valid) = parse_callback_request(request, expected_csrf);
        assert_eq!(code, Some("some_code".to_string()));
        assert!(state_valid);
    }
}
