use crate::handlers::auth::WebhookAuth;
use crate::handlers::webhook_util::{extract_user_id, prepare_github_issue};
use crate::models::WebhookRequest;
use crate::state::ProxyState;
use crate::state::core::EventAction;
use crate::state::spool::{EvictRequest, GitHubTicket};
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::{State, post};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, warn};
use wazuh_cert_oauth2_model::models::revoke_request::RevokeRequest;

#[post("/webhook", format = "application/json", data = "<payload>")]
#[tracing::instrument(skip(_auth, state, payload), fields(event_type = %payload.event_type, resource = ?payload.resource_path))]
pub async fn send_webhook(
    _auth: WebhookAuth,
    state: &State<ProxyState>,
    payload: Json<WebhookRequest>,
) -> Result<Status, Status> {
    let p = payload.into_inner();
    debug!("received webhook: {:?}", p);
    let et_lower = p.event_type.to_ascii_lowercase();
    let action = state.is_allowed_event(&et_lower, &p);

    match action {
        EventAction::Ignore => {
            info!(
                "ignored webhook event type={} resourcePath={:?}",
                p.event_type, p.resource_path
            );
            Ok(Status::Ok)
        }
        EventAction::Revoke => handle_revoke(state, p).await,
        EventAction::Enabled => handle_enable(state, p).await,
        EventAction::CreateTicket => handle_create_ticket(state, p).await,
    }
}

#[tracing::instrument(skip(state, p), fields(event_type = %p.event_type))]
async fn handle_create_ticket(
    state: &State<ProxyState>,
    p: WebhookRequest,
) -> Result<Status, Status> {
    let (title, body) = prepare_github_issue(&p);
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

#[tracing::instrument(skip(state), fields(event_type = %p.event_type))]
async fn handle_enable(state: &State<ProxyState>, p: WebhookRequest) -> Result<Status, Status> {
    info!(
        "handling enable event; type={} resourcePath={:?}",
        p.event_type, p.resource_path
    );
    // On enable: cancel any queued revoke requests for the subject to avoid
    // revoking immediately after a quick re-enable.
    if let Some(subject) = extract_user_id(&p) {
        match state.cancel_pending_revokes_for_subject(&subject).await {
            Ok(n) => info!("canceled {} pending revokes for subject {}", n, subject),
            Err(e) => warn!("failed to cancel pending revokes for {}: {}", subject, e),
        }
    } else {
        debug!("enable event without subject; nothing to cancel");
    }
    // No upstream "unrevoke"; return OK
    Ok(Status::Ok)
}

#[tracing::instrument(skip(state), fields(event_type = %p.event_type))]
async fn handle_revoke(state: &State<ProxyState>, p: WebhookRequest) -> Result<Status, Status> {
    let subject = extract_user_id(&p);
    if subject.is_none() {
        warn!(
            "webhook event missing userId; type={} details={:?} resource={:?}",
            p.event_type, p.details, p.resource_path
        );
        return Ok(Status::Ok);
    }
    let subject = subject.unwrap();
    let reason = state.revoke_reason();

    let reason_str = reason.as_deref().unwrap_or("");

    // Fetch the active ledger entry *before* forwarding the revoke so the
    // wazuh_agent_name is still present on the active entry.
    let wazuh_agent_name = if !reason_str.to_ascii_lowercase().starts_with("auto-rotate") && !reason_str.is_empty() {
        match state.fetch_ledger_by_subject(&subject).await {
            Ok(entries) => entries
                .iter()
                .filter(|e| !e.revoked && e.wazuh_agent_name.is_some())
                .last()
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
        reason: reason.clone(),
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
