use wazuh_cert_oauth2_model::models::errors::AppResult;
use wazuh_cert_oauth2_model::models::sign_csr_request::SignCsrRequest;
use wazuh_cert_oauth2_model::models::signed_cert_response::SignedCertResponse;
use wazuh_cert_oauth2_model::services::http_client::HttpClient;

/// Submit a CSR to the server for signing.
pub async fn submit_csr(
    http: &HttpClient,
    endpoint: &str,
    token: &str,
    csr_pem: &str,
    overwrite: bool,
    agent_name: Option<&str>,
) -> AppResult<SignedCertResponse> {
    let dto = SignCsrRequest {
        csr_pem: csr_pem.to_string(),
        overwrite: Some(overwrite),
        wazuh_agent_name: agent_name.map(|s| s.to_string()),
    };
    http.post_json_auth(endpoint, token, &dto).await
}

#[cfg(test)]
mod tests {
    use super::submit_csr;
    use wazuh_cert_oauth2_model::services::http_client::HttpClient;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn submit_csr_posts_dto_with_bearer_auth() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/register-agent"))
            .and(header("authorization", "Bearer tok-123"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                r#"{"certificate_pem":"CERT","ca_cert_pem":"CA"}"#,
                "application/json",
            ))
            .mount(&server)
            .await;

        let http = HttpClient::new_with_defaults().expect("http client");
        let resp = submit_csr(
            &http,
            &format!("{}/register-agent", server.uri()),
            "tok-123",
            "CSR-PEM",
            true,
            Some("agent-1"),
        )
        .await
        .expect("submit should succeed");

        assert_eq!(resp.certificate_pem, "CERT");
        assert_eq!(resp.ca_cert_pem, "CA");
    }
}
