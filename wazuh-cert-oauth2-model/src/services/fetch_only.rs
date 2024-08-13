use anyhow::Result;
use reqwest::Client;
use serde::de::DeserializeOwned;

pub async fn fetch_only<R: DeserializeOwned>(url: &str) -> Result<R> {
    let jwks = Client::new()
        .get(url)
        .send()
        .await?
        .json()
        .await?;

    Ok(jwks)
}