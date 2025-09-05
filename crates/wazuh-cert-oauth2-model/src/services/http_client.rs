use std::time::Duration;

use anyhow::Result;
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde::Serialize;

#[derive(Clone)]
pub struct HttpClient {
    client: Client,
}

impl HttpClient {
    pub fn new_with_defaults() -> Result<Self> {
        let client = Client::builder()
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(16)
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .tcp_keepalive(Duration::from_secs(60))
            .build()?;
        Ok(Self { client })
    }

    pub fn from_client(client: Client) -> Self {
        Self { client }
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub async fn fetch_json<R: DeserializeOwned>(&self, url: &str) -> Result<R> {
        let resp = self
            .client
            .get(url)
            .send()
            .await?
            .error_for_status()?;
        Ok(resp.json().await?)
    }

    pub async fn post_json<B: Serialize, R: DeserializeOwned>(&self, url: &str, body: &B) -> Result<R> {
        let resp = self
            .client
            .post(url)
            .json(body)
            .send()
            .await?
            .error_for_status()?;
        Ok(resp.json().await?)
    }

    pub async fn post_json_auth<B: Serialize, R: DeserializeOwned>(&self, url: &str, token: &str, body: &B) -> Result<R> {
        let resp = self
            .client
            .post(url)
            .bearer_auth(token)
            .json(body)
            .send()
            .await?
            .error_for_status()?;
        Ok(resp.json().await?)
    }
}

