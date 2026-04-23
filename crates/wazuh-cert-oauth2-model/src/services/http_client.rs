use std::time::Duration;

use crate::models::errors::AppResult;
use reqwest::Client;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::instrument;

#[derive(Clone)]
pub struct HttpClient {
    client: Client,
}

impl HttpClient {
    #[instrument]
    pub fn new_with_defaults() -> AppResult<Self> {
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

    #[instrument(level = "debug", skip(self))]
    pub async fn fetch_json<R: DeserializeOwned>(&self, url: &str) -> AppResult<R> {
        let resp = self.client.get(url).send().await?.error_for_status()?;
        Ok(resp.json().await?)
    }

    #[instrument(level = "debug", skip(self, body))]
    pub async fn post_json<B: Serialize, R: DeserializeOwned>(
        &self,
        url: &str,
        body: &B,
    ) -> AppResult<R> {
        let resp = self
            .client
            .post(url)
            .json(body)
            .send()
            .await?
            .error_for_status()?;
        Ok(resp.json().await?)
    }

    #[instrument(level = "debug", skip(self, token, body))]
    pub async fn post_json_auth<B: Serialize, R: DeserializeOwned>(
        &self,
        url: &str,
        token: &str,
        body: &B,
    ) -> AppResult<R> {
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

#[cfg(test)]
mod tests {
    use super::HttpClient;
    use serde_json::{Value, json};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn spawn_one_shot_json_server(
        response_body: &'static str,
    ) -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener should have addr");
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept should work");
            let mut buf = vec![0u8; 8192];
            let n = socket.read(&mut buf).await.expect("read should work");
            let req = String::from_utf8_lossy(&buf[..n]).to_string();

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            socket
                .write_all(response.as_bytes())
                .await
                .expect("write should work");
            req
        });
        (format!("http://{}", addr), handle)
    }

    #[tokio::test]
    async fn fetch_json_deserializes_response_body() {
        let (base_url, handle) = spawn_one_shot_json_server(r#"{"status":"ok"}"#).await;
        let url = format!("{}/health", base_url);
        let client = HttpClient::new_with_defaults().expect("client should build");

        let body: Value = client.fetch_json(&url).await.expect("fetch should work");
        assert_eq!(body["status"], "ok");

        let req = handle.await.expect("server task should complete");
        assert!(req.starts_with("GET /health HTTP/1.1"));
    }

    #[tokio::test]
    async fn post_json_auth_sends_bearer_header_and_json_body() {
        let (base_url, handle) = spawn_one_shot_json_server(r#"{"accepted":true}"#).await;
        let url = format!("{}/api/revoke", base_url);
        let client = HttpClient::new_with_defaults().expect("client should build");

        let body = json!({ "subject": "user-1", "reason": "test" });
        let resp: Value = client
            .post_json_auth(&url, "token-123", &body)
            .await
            .expect("post should work");
        assert_eq!(resp["accepted"], true);

        let req = handle.await.expect("server task should complete");
        assert!(req.starts_with("POST /api/revoke HTTP/1.1"));
        let req_lower = req.to_ascii_lowercase();
        assert!(req_lower.contains("authorization: bearer token-123"));
        assert!(req.contains("\"subject\":\"user-1\""));
        assert!(req.contains("\"reason\":\"test\""));
    }
}
