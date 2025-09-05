use anyhow::Result;
use wazuh_cert_oauth2_model::models::claims::Claims;
use wazuh_cert_oauth2_model::models::document::DiscoveryDocument;
use wazuh_cert_oauth2_model::services::http_client::HttpClient;
use wazuh_cert_oauth2_model::services::jwks::validate_token;

use crate::services::generate_csr::generate_key_and_csr;
use crate::services::get_token::{get_token, GetTokenParams};
use crate::services::restart_agent::restart_agent;
use crate::services::save_to_file::save_cert_and_key;
use crate::services::set_name::set_name;
use crate::services::stop_agent::stop_agent;
use crate::services::submit_csr::submit_csr;

#[inline]
pub async fn run_oauth2_flow(
    issuer: &str,
    audience_csv: &str,
    client_id: &str,
    client_secret: Option<&String>,
    endpoint: &str,
    is_service_account: bool,
    cert_path: &str,
    key_path: &str,
    agent_control: bool,
) -> Result<()> {
    let kc_audiences = audience_csv.split(',').map(|s| s.to_string()).collect::<Vec<String>>();
    let http = HttpClient::new_with_defaults()?;
    let document: DiscoveryDocument = http.fetch_json(&format!("{}/.well-known/openid-configuration", issuer)).await?;
    if agent_control { info!("Stopping agent"); stop_agent().await?; }
    info!("Getting JWKS");
    let jwks = http.fetch_json(&document.jwks_uri).await?;
    debug!("Getting token");
    let token = get_token(&http, GetTokenParams { document, client_id: client_id.to_string(), client_secret: client_secret.cloned(), is_service_account }).await?;
    debug!("Validating token & getting the name claim");
    let Claims { name, sub, .. } = validate_token(&token, &jwks, &kc_audiences).await?;
    debug!("Generating keypair and CSR");
    let (csr_pem, private_key_pem) = generate_key_and_csr(&sub)?;
    debug!("Submitting CSR for signing");
    let signed = submit_csr(&http, endpoint, &token, &csr_pem).await?;
    debug!("Saving certificate and private key");
    save_cert_and_key(cert_path, key_path, &signed.certificate_pem, &private_key_pem, Some(&signed.ca_cert_pem)).await?;
    if agent_control { debug!("Setting name"); set_name(&name).await?; }
    if agent_control { debug!("Restarting agent"); restart_agent().await?; }
    info!("Name set successfully!");
    Ok(())
}

