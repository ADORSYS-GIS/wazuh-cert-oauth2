use anyhow::Result;
use reqwest::Client;

use wazuh_cert_oauth2_model::models::register_agent_dto::RegisterAgentDto;
use wazuh_cert_oauth2_model::models::user_key::UserKey;

/// Fetch the user keys from the OAuth2 server.
pub async fn fetch_user_keys(endpoint: &str, token: &str) -> Result<UserKey> {
    let client = Client::new();

    // Create a new agent dto
    let dto = RegisterAgentDto {};
    let user_keys = client.post(endpoint)
        .bearer_auth(token)
        .json(&dto)
        .send().await?
        .json().await?;

    Ok(user_keys)
}