use wazuh_cert_oauth2_model::models::document::DiscoveryDocument;
use wazuh_cert_oauth2_model::models::errors::{AppError, AppResult};
use wazuh_cert_oauth2_model::services::http_client::HttpClient;
use wazuh_cert_oauth2_model::services::jwks::validate_token;

use crate::services::generate_csr::generate_key_and_csr;
use crate::services::get_token::{GetTokenParams, get_token};
use crate::services::restart_agent::restart_agent;
use crate::services::save_to_file::save_cert_and_key;
use crate::services::set_name::set_name;
use crate::services::stop_agent::stop_agent;
use crate::services::submit_csr::submit_csr;

#[derive(Debug, Clone)]
pub struct FlowParams {
    pub issuer: String,
    pub audience_csv: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub endpoint: String,
    pub is_service_account: bool,
    pub cert_path: String,
    pub ca_cert_path: String,
    pub key_path: String,
    pub agent_control: bool,
}

pub async fn run_oauth2_flow(params: &FlowParams) -> AppResult<()> {
    let kc_audiences = params
        .audience_csv
        .split(',')
        .map(|s| s.to_string())
        .collect::<Vec<String>>();
    let http = HttpClient::new_with_defaults()?;
    let document: DiscoveryDocument = http
        .fetch_json(&format!(
            "{}/.well-known/openid-configuration",
            params.issuer
        ))
        .await?;
    if params.agent_control {
        info!("Stopping agent");
        stop_agent().await?;
    }
    info!("Getting JWKS");
    let jwks = http.fetch_json(&document.jwks_uri).await?;

    debug!("Getting token");
    let token = get_token(
        &http,
        GetTokenParams {
            document,
            client_id: params.client_id.clone(),
            client_secret: params.client_secret.clone(),
            is_service_account: params.is_service_account,
        },
    )
    .await?;

    debug!("Validating token & getting the name claim");
    let claims = validate_token(&token, &jwks, &Some(kc_audiences)).await?;
    let sub = claims.sub.clone();

    debug!("Generating keypair and CSR");
    let (csr_pem, private_key_pem) = generate_key_and_csr(&sub)?;

    debug!("Submitting CSR for signing");
    let signed = submit_csr(&http, &params.endpoint, &token, &csr_pem).await?;

    debug!("Saving certificate and private key");
    save_cert_and_key(
        &params.cert_path,
        &params.key_path,
        &signed.certificate_pem,
        &private_key_pem,
        &params.ca_cert_path,
        Some(&signed.ca_cert_pem),
    )
    .await?;

    if params.agent_control {
        if let Some(name) = claims.get_name() {
            debug!("Setting name");
            set_name(&name).await?;
        } else {
            return Err(AppError::JwtMissingName);
        }

        info!("Name set successfully!");

        debug!("Restarting agent");
        restart_agent().await?;
    }

    Ok(())
}
