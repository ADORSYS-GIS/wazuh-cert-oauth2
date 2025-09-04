use anyhow::Result;
use reqwest::Client;
use wazuh_cert_oauth2_model::models::sign_csr_request::SignCsrRequest;
use wazuh_cert_oauth2_model::models::signed_cert_response::SignedCertResponse;

/// Submit a CSR to the server for signing
pub async fn submit_csr(endpoint: &str, token: &str, csr_pem: &str) -> Result<SignedCertResponse> {
    let client = Client::new();
    let dto = SignCsrRequest { csr_pem: csr_pem.to_string() };

    let resp = client
        .post(endpoint)
        .bearer_auth(token)
        .json(&dto)
        .send()
        .await?
        .error_for_status()?;

    Ok(resp.json().await?)
}

