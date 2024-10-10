use anyhow::Result;
use reqwest::Client;
use serde::de::DeserializeOwned;

/// Fetch the content of the specified URL.
pub async fn fetch_only<R: DeserializeOwned>(url: &str) -> Result<R> {
    let jwks = Client::new()
        .get(url)
        .send()
        .await?
        .json()
        .await?;

    Ok(jwks)
}