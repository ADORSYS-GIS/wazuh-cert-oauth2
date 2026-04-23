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
use crate::shared::cli::Opt;

#[derive(Debug, Clone)]
pub struct FlowParams {
    issuer: String,
    audience_csv: String,
    client_id: String,
    client_secret: Option<String>,
    endpoint: String,
    is_service_account: bool,
    cert_path: String,
    ca_cert_path: String,
    key_path: String,
    agent_control: bool,
    timeout_secs: u64,
}

impl From<Opt> for FlowParams {
    fn from(value: Opt) -> Self {
        match value {
            Opt::OAuth2 {
                issuer,
                audience,
                client_id,
                client_secret,
                endpoint,
                is_service_account,
                cert_path,
                ca_cert_path,
                key_path,
                agent_control,
                timeout_secs,
            } => Self {
                issuer,
                audience_csv: audience,
                client_id,
                client_secret,
                endpoint,
                is_service_account,
                cert_path,
                key_path,
                agent_control,
                ca_cert_path,
                timeout_secs,
            },
        }
    }
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
            timeout_secs: params.timeout_secs,
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

#[cfg(test)]
mod tests {
    use super::FlowParams;
    use crate::shared::cli::Opt;

    #[test]
    fn flow_params_are_mapped_from_oauth2_opt() {
        let opt = Opt::OAuth2 {
            issuer: "https://issuer.example/realms/demo".to_string(),
            audience: "account,api".to_string(),
            client_id: "client-id".to_string(),
            client_secret: Some("client-secret".to_string()),
            endpoint: "https://cert.example/api/register-agent".to_string(),
            is_service_account: true,
            cert_path: "/tmp/client.cert".to_string(),
            ca_cert_path: "/tmp/ca.pem".to_string(),
            key_path: "/tmp/client.key".to_string(),
            agent_control: false,
            timeout_secs: 120,
        };

        let params = FlowParams::from(opt);

        assert_eq!(params.issuer, "https://issuer.example/realms/demo");
        assert_eq!(params.audience_csv, "account,api");
        assert_eq!(params.client_id, "client-id");
        assert_eq!(params.client_secret.as_deref(), Some("client-secret"));
        assert_eq!(params.endpoint, "https://cert.example/api/register-agent");
        assert!(params.is_service_account);
        assert_eq!(params.cert_path, "/tmp/client.cert");
        assert_eq!(params.ca_cert_path, "/tmp/ca.pem");
        assert_eq!(params.key_path, "/tmp/client.key");
        assert!(!params.agent_control);
    }
}
