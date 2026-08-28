use std::path::PathBuf;
use std::sync::Arc;

use reqwest::Client;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use wazuh_cert_oauth2_model::models::errors::{AppError, AppResult};
use wazuh_cert_oauth2_model::services::wazuh::WazuhClient;

use crate::migrate::v1::client;
use crate::migrate::v1::csv::{self, UnresolvedEntry};
use crate::migrate::v1::matcher::{self, MatchResult, MatchStatus};
use crate::migrate::v1::opts::MigrateOpt;
use crate::migrate::v1::report;
use wazuh_cert_oauth2_model::services::wazuh::AgentItem;

pub async fn run_migration(opt: MigrateOpt) -> AppResult<()> {
    info!("Authenticating with Wazuh Manager...");
    let wazuh = WazuhClient::with_tls_options(
        opt.wazuh_manager_url.clone(),
        Some(opt.wazuh_api_user.clone()),
        Some(opt.wazuh_api_password.clone()),
        None,
        opt.wazuh_tls_verify,
        opt.wazuh_ca_bundle.clone(),
    );
    let agents = wazuh.list_agents().await?;
    if agents.is_empty() {
        return Err(AppError::UpstreamError(
            "No agents found in Wazuh Manager — nothing to match".into(),
        ));
    }

    debug!(
        agent_names = ?agents.iter().map(|a| (a.id.as_str(), a.name.as_str())).collect::<Vec<_>>(),
        "Wazuh agents available for matching"
    );

    let kc_client = build_kc_client(&opt)?;
    info!(
        "Authenticating with Keycloak Admin API (method: {})...",
        opt.keycloak_auth_method
    );
    let mut kc_session = client::KeycloakSession::new(kc_client, opt.clone());
    let kc_available = kc_session.get_token().await?.is_some();
    if kc_available {
        info!("Keycloak admin authentication successful");
    } else {
        info!("Keycloak unavailable — will only keep entries with an existing agent_name");
    }

    let input_path = PathBuf::from(&opt.input);
    if !input_path.exists() {
        return Err(AppError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Input ledger CSV not found: {}", opt.input),
        )));
    }
    info!("Processing ledger CSV: {}", opt.input);
    let content = tokio::fs::read_to_string(&input_path).await?;
    let entries = crate::shared::ledger::csv::parse_csv(&content)?;
    info!("Read {} ledger entries", entries.len());
    if entries.is_empty() {
        return Err(AppError::UpstreamError("No ledger entries found".into()));
    }

    let mut migrated = Vec::with_capacity(entries.len());
    let mut unresolved: Vec<UnresolvedEntry> = Vec::new();
    let mut results: Vec<Option<MatchResult>> = Vec::with_capacity(entries.len());
    let mut statuses: Vec<MatchStatus> = Vec::with_capacity(entries.len());

    for entry in &entries {
        if entry.revoked {
            statuses.push(MatchStatus::SkippedRevoked);
            results.push(None);
            migrated.push(entry.clone());
            continue;
        }

        let (result, status, reason) = if entry.wazuh_agent_name.is_some() {
            (
                None,
                MatchStatus::SkippedAlreadyPresent,
                "skipped_already_present".to_string(),
            )
        } else {
            let (r, s) = match_entry(entry, &agents, &mut kc_session).await;
            let reason = match &s {
                MatchStatus::Matched => "keycloak_match".to_string(),
                MatchStatus::AmbiguousMultipleAgents(candidates) => {
                    let ids: Vec<&str> = candidates.iter().map(|(id, _)| id.as_str()).collect();
                    let names: Vec<&str> =
                        candidates.iter().map(|(_, name)| name.as_str()).collect();
                    format!(
                        "ambiguous_multiple_agents: candidates=[{}] ids=[{}]",
                        names.join(", "),
                        ids.join(", "),
                    )
                }
                MatchStatus::UnmatchedNoKeycloak => "unmatched_no_keycloak".to_string(),
                MatchStatus::UnmatchedNoMatch => "unmatched_no_match".to_string(),
                _ => "unknown".to_string(),
            };
            (r, s, reason)
        };

        statuses.push(status);
        results.push(result.clone());
        migrated.push(wazuh_cert_oauth2_model::models::ledger_entry::LedgerEntry {
            subject: entry.subject.clone(),
            serial_hex: entry.serial_hex.clone(),
            issued_at_unix: entry.issued_at_unix,
            not_after_unix: entry.issued_at_unix
                + wazuh_cert_oauth2_model::models::ledger_entry::CERTIFICATE_VALIDITY_DAYS * 86400,
            revoked: entry.revoked,
            revoked_at_unix: entry.revoked_at_unix,
            reason: entry.reason.clone(),
            issuer: entry.issuer.clone(),
            realm: entry.realm.clone(),
            wazuh_agent_name: entry
                .wazuh_agent_name
                .clone()
                .or_else(|| result.as_ref().map(|m| m.agent_name.clone())),
        });

        match &result {
            Some(m) => info!("Matched {} → {}", entry.subject, m.agent_name),
            None if entry.wazuh_agent_name.is_some() => {
                info!("Skipped {} (already has agent_name)", entry.subject);
            }
            None => {
                warn!("Unmatched {} (reason={})", entry.subject, reason);
                unresolved.push(UnresolvedEntry {
                    subject: entry.subject.clone(),
                    serial_hex: entry.serial_hex.clone(),
                    issued_at_unix: entry.issued_at_unix,
                    reason,
                });
            }
        }
    }

    if !unresolved.is_empty() {
        let unresolved_path = PathBuf::from(&opt.unresolved);
        csv::write_unresolved_csv(&unresolved_path, &unresolved)?;
        info!(
            "Wrote {} unresolved entries to {}",
            unresolved.len(),
            opt.unresolved
        );
    }

    let output_path = PathBuf::from(&opt.output);
    let shared = Arc::new(RwLock::new(migrated));
    crate::shared::ledger::csv::persist_csv(&output_path, &shared).await?;
    info!("Wrote migrated CSV to {}", opt.output);

    let report_text = report::generate(
        &entries,
        &results,
        &statuses,
        agents.len(),
        kc_available,
        &opt,
    );
    let report_path = PathBuf::from(&opt.report);
    std::fs::write(&report_path, report_text.as_bytes())?;
    println!("{}", report_text);

    info!("Migration complete");
    Ok(())
}

async fn match_entry(
    entry: &wazuh_cert_oauth2_model::models::ledger_entry::LedgerEntry,
    agents: &[AgentItem],
    kc_session: &mut client::KeycloakSession,
) -> (Option<MatchResult>, MatchStatus) {
    let kc_token = match kc_session.get_token().await {
        Ok(t) => t,
        Err(e) => {
            warn!(entry.subject, error = %e, "Keycloak token refresh failed");
            None
        }
    };
    if let Some(ref token) = kc_token
        && let Some(kc_name) = client::keycloak_lookup_user(
            kc_session.client(),
            kc_session.opt(),
            token,
            &entry.subject,
        )
        .await
    {
        match matcher::find_match(&kc_name, agents) {
            Ok(Some(m)) => return (Some(m), MatchStatus::Matched),
            Err(candidates) => {
                return (None, MatchStatus::AmbiguousMultipleAgents(candidates));
            }
            Ok(None) => {}
        }
    }

    if kc_token.is_none() {
        (None, MatchStatus::UnmatchedNoKeycloak)
    } else {
        (None, MatchStatus::UnmatchedNoMatch)
    }
}

fn build_kc_client(opt: &MigrateOpt) -> AppResult<Client> {
    let mut builder = Client::builder();
    if !opt.keycloak_tls_verify {
        builder = builder.danger_accept_invalid_certs(true);
    }
    if let Some(ref ca_path) = opt.keycloak_ca_bundle {
        let cert_pem = std::fs::read_to_string(ca_path)?;
        let cert = reqwest::Certificate::from_pem(cert_pem.as_bytes())
            .map_err(|e| AppError::UpstreamError(format!("invalid Keycloak CA cert: {}", e)))?;
        builder = builder.add_root_certificate(cert);
    }
    builder
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| AppError::UpstreamError(format!("failed to build HTTP client: {}", e)))
}
