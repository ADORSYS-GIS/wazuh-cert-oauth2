use anyhow::Result;
use wazuh_cert_oauth2_model::models::sign_csr_request::SignCsrRequest;
use wazuh_cert_oauth2_model::models::signed_cert_response::SignedCertResponse;
use wazuh_cert_oauth2_model::services::http_client::HttpClient;

/// Submit a CSR to the server for signing
pub async fn submit_csr(
    http: &HttpClient,
    endpoint: &str,
    token: &str,
    csr_pem: &str,
) -> Result<SignedCertResponse> {
    let dto = SignCsrRequest {
        csr_pem: csr_pem.to_string(),
    };
    http.post_json_auth(endpoint, token, &dto).await
}
