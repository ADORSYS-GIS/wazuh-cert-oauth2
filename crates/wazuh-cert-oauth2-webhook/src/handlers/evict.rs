use crate::handlers::auth::WebhookAuth;
use crate::state::ProxyState;
use crate::state::spool::EvictRequest;
use crate::state::wazuh_api::EvictionOutcome;
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::{State, post};
use tracing::info;

/// Internal endpoint for the cert server to trigger eviction after auto-rotate override.
/// This allows the webhook to own all Wazuh manager interactions.
#[post("/internal/evict", format = "application/json", data = "<req>")]
#[tracing::instrument(skip(_auth, state, req), fields(subject = %req.subject))]
pub async fn internal_evict(
    _auth: WebhookAuth,
    state: &State<ProxyState>,
    req: Json<EvictRequest>,
) -> Result<Status, Status> {
    let req = req.into_inner();
    info!(
        subject = %req.subject,
        agent_name = ?req.wazuh_agent_name,
        reason = %req.reason,
        "Received internal eviction request"
    );

    match state.run_eviction_from_state(req.clone()).await {
        Ok(EvictionOutcome::Done) => {}
        Ok(EvictionOutcome::Pending(updated_req)) => {
            // Grace period started — queue the updated request for later processing.
            if let Err(qe) = state.queue_evict(updated_req).await {
                tracing::error!(
                    subject = %req.subject,
                    "Failed to queue pending eviction: {}",
                    qe
                );
                return Err(Status::InternalServerError);
            }
        }
        Err(e) => {
            tracing::warn!(subject = %req.subject, "Eviction failed, queuing for retry: {}", e);
            if let Err(qe) = state.queue_evict(req).await {
                tracing::error!(
                    "Eviction failed AND spool queue failed — request lost: {}",
                    qe
                );
                return Err(Status::InternalServerError);
            }
        }
    }

    Ok(Status::Accepted)
}
