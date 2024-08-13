use oauth2::{ClientId, ClientSecret, AuthUrl, TokenUrl, RedirectUrl, AuthorizationCode};
use oauth2::basic::BasicClient;
use oauth2::reqwest::http_client;

pub async fn get_token(issuer: &str, client_id: &str, client_secret: &str) -> Result<String, Box<dyn std::error::Error>> {
    let client = BasicClient::new(
        ClientId::new(client_id.to_string()),
        Some(ClientSecret::new(client_secret.to_string())),
        AuthUrl::new(format!("{}/authorize", issuer))?,
        Some(TokenUrl::new(format!("{}/token", issuer))?)
    ).set_redirect_uri(RedirectUrl::new("urn:ietf:wg:oauth:2.0:oob".to_string())?);

    // User needs to go to the authorization URL manually
    let auth_url = client.authorize_url().url();

    println!("Please open this URL in your browser:\n{}\n", auth_url);

    println!("Enter the authorization code:");
    let mut auth_code = String::new();
    std::io::stdin().read_line(&mut auth_code)?;
    let code = AuthorizationCode::new(auth_code.trim().to_string());

    let token_result = client.exchange_code(code).request_async(http_client).await?;

    Ok(token_result.access_token().secret().clone())
}
