use anyhow::Result;
use reqwest::Client;
use serde::de::DeserializeOwned;

/// Fetch the content of the specified URL.
pub async fn fetch_only<R: DeserializeOwned>(http: &Client, url: &str) -> Result<R> {
    let resp = http
        .get(url)
        .send()
        .await?
        .error_for_status()?;
    Ok(resp.json().await?)
}
