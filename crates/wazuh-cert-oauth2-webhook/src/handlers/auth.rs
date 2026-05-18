use rocket::http::{HeaderMap, Status};
use rocket::request::{FromRequest, Outcome, Request};

use crate::ports::webhook_auth::AuthOutcome;
use crate::state::ProxyState;
use tracing::warn;

pub struct WebhookAuth<'r>(pub &'r HeaderMap<'r>);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for WebhookAuth<'r> {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let state = match request.rocket().state::<ProxyState>() {
            Some(s) => s,
            None => return Outcome::Error((Status::InternalServerError, ())),
        };

        match state.webhook_auth.authenticate(request.headers()).await {
            AuthOutcome::Authenticated => Outcome::Success(WebhookAuth(request.headers())),
            AuthOutcome::NotApplicable => {
                warn!("Webhook auth: no applicable auth scheme found — treating as Unauthorized");
                Outcome::Error((Status::Unauthorized, ()))
            }
            AuthOutcome::Denied => Outcome::Error((Status::Unauthorized, ())),
        }
    }
}
