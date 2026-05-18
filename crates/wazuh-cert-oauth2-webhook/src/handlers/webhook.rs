use crate::handlers::auth::WebhookAuth;
use crate::ports::idp::IdpEvent;
use crate::state::ProxyState;
use crate::state::spool::{EvictRequest, GitHubTicket};
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::{State, post};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, warn};
use wazuh_cert_oauth2_model::models::revoke_request::RevokeRequest;

#[post("/webhook", format = "application/json", data = "<payload>")]
#[tracing::instrument(skip(auth, state, payload))]
pub async fn send_webhook(
    auth: WebhookAuth<'_>,
    state: &State<ProxyState>,
    payload: Json<serde_json::Value>,
) -> Result<Status, Status> {
    let p = payload.into_inner();
    debug!("received webhook: {}", p);

    let action = state.idp_parse_event(auth.0, &p);

    match action {
        IdpEvent::Ignore => {
            info!("ignored webhook event");
            Ok(Status::Ok)
        }
        IdpEvent::UserRevoke { subject } => handle_revoke(state, &p, subject).await,
        IdpEvent::UserCreate { .. } => handle_create_ticket(state, &p).await,
    }
}

async fn handle_create_ticket(
    state: &State<ProxyState>,
    p: &serde_json::Value,
) -> Result<Status, Status> {
    let user = match state.idp_extract_user(p) {
        Ok(u) => u,
        Err(e) => {
            warn!(
                "failed to extract user from webhook for ticket creation: {}",
                e
            );
            return Ok(Status::Ok);
        }
    };

    let title = format!(
        "[IDP] User Created: {}",
        user.username.as_deref().unwrap_or("unknown")
    );
    let body = format!(
        "ID: {:?}\nUsername: {:?}\nEmail: {:?}\nEnabled: {}",
        user.id, user.username, user.email, user.enabled
    );
    let ticket = GitHubTicket { title, body };

    if let Err(e) = state.forward_github_ticket_with_retry(ticket.clone()).await {
        warn!(
            "initial GitHub ticket creation failed; spooling for retry: {}",
            e
        );
        if let Err(se) = state.queue_github_ticket(ticket).await {
            error!("CRITICAL: failed to spool GitHub ticket: {}", se);
            return Err(Status::InternalServerError);
        }
    }

    // We return Ok always to avoid Keycloak retrying the webhook indefinitely
    // if the GitHub API is having issues.
    Ok(Status::Ok)
}

async fn handle_revoke(
    state: &State<ProxyState>,
    p: &serde_json::Value,
    subject: String,
) -> Result<Status, Status> {
    // Subject should be provided by the adapter in IdpEvent::UserRevoke
    if subject.is_empty() {
        warn!("webhook event missing subject; ignoring. payload={}", p);
        return Ok(Status::Ok);
    }

    let reason = state.revoke_reason();
    let reason_str = reason.as_str();

    // Fetch the active ledger entry *before* forwarding the revoke so the
    // wazuh_agent_name is still present on the active entry.
    let wazuh_agent_name =
        if !reason_str.to_ascii_lowercase().starts_with("auto-rotate") && !reason_str.is_empty() {
            match state.fetch_ledger_by_subject(&subject).await {
                Ok(entries) => entries
                    .iter()
                    .rfind(|e| !e.revoked && e.wazuh_agent_name.is_some())
                    .and_then(|e| e.wazuh_agent_name.clone()),
                Err(e) => {
                    warn!(subject = %subject, "Failed to fetch ledger from server: {}", e);
                    None
                }
            }
        } else {
            None
        };

    let req = RevokeRequest {
        serial_hex: None,
        subject: Some(subject.clone()),
        reason: Some(reason.clone()),
    };
    match state.forward_revoke_with_retry(req.clone()).await {
        Ok(()) => {}
        Err(e) => {
            warn!("immediate forward failed: {} — queueing", e);
            if let Err(qe) = state.queue_revoke(req).await {
                error!("CRITICAL: failed to spool revoke: {}", qe);
                return Err(Status::InternalServerError);
            }
        }
    }

    if reason_str.to_ascii_lowercase().starts_with("auto-rotate") {
        debug!(
            subject = %subject,
            reason = %reason_str,
            "Skipping eviction for auto-rotate revocation"
        );
    } else if !reason_str.is_empty() {
        let triggered_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let evict_req = EvictRequest {
            subject: subject.clone(),
            wazuh_agent_name,
            reason: reason_str.to_string(),
            triggered_at_unix,
        };
        info!(
            subject = %subject,
            reason = %reason_str,
            "Queuing eviction for revoked certificate"
        );
        if let Err(e) = state.queue_evict(evict_req).await {
            error!(
                "CRITICAL: failed to spool eviction request for {}: {}",
                subject, e
            );
        }
    } else {
        warn!(
            subject = %subject,
            "Revocation has no reason; skipping eviction"
        );
    }

    Ok(Status::Ok)
}
