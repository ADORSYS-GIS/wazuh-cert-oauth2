use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

use crate::state::ProxyState;
use tracing::{debug, info, warn};

pub struct WebhookAuth;

fn constant_time_eq(a: &str, b: &str) -> bool {
    // Constant-time comparison over bytes, independent of early differences.
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    let max = ab.len().max(bb.len());
    let mut diff: u8 = (ab.len() ^ bb.len()) as u8;
    for i in 0..max {
        let av = *ab.get(i).unwrap_or(&0);
        let bv = *bb.get(i).unwrap_or(&0);
        diff |= av ^ bv;
    }
    diff == 0
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for WebhookAuth {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let state = match request.rocket().state::<ProxyState>() {
            Some(s) => s,
            None => return Outcome::Error((Status::InternalServerError, ())),
        };

        // If no credential configured, allow all
        if state.webhook_allows_anonymous() {
            info!("Webhook auth: anonymous allowed by config");
            return Outcome::Success(WebhookAuth);
        }

        // Check API key header first
        if let Some(cfg_key) = state.webhook_api_key()
            && let Some(h) = request.headers().get_one("X-API-KEY")
            && constant_time_eq(h, cfg_key)
        {
            info!("Webhook auth: X-API-KEY validated");
            return Outcome::Success(WebhookAuth);
        }

        // Authorization: Basic ... or Bearer ...
        if let Some(authz) = request.headers().get_one("Authorization") {
            if let Some(token) = authz.strip_prefix("Bearer ") {
                if let Some(cfg) = state.webhook_bearer_token()
                    && constant_time_eq(token, cfg)
                {
                    info!("Webhook auth: Bearer token validated");
                    return Outcome::Success(WebhookAuth);
                }
                debug!("Webhook auth: Bearer token failed validation");
            } else if let Some(b64) = authz.strip_prefix("Basic ")
                && let (Some(u), Some(p)) =
                    (state.webhook_basic_user(), state.webhook_basic_password())
                && let Ok(decoded) = B64.decode(b64.as_bytes())
                && let Ok(s) = String::from_utf8(decoded)
            {
                let mut parts = s.splitn(2, ':');
                let user_ok = parts
                    .next()
                    .map(|x| constant_time_eq(x, u))
                    .unwrap_or(false);
                let pass_ok = parts
                    .next()
                    .map(|x| constant_time_eq(x, p))
                    .unwrap_or(false);
                if user_ok && pass_ok {
                    info!("Webhook auth: Basic credentials validated");
                    return Outcome::Success(WebhookAuth);
                }
                debug!("Webhook auth: Basic credentials invalid");
            }
        } else {
            debug!("Webhook auth: no Authorization header present");
        }
        warn!("Webhook auth: unauthorized request");
        Outcome::Error((Status::Unauthorized, ()))
    }
}
