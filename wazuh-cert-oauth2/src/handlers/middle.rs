use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};

use wazuh_cert_oauth2_model::models::claims::Claims;
use wazuh_cert_oauth2_model::services::jwks::validate_token;

use crate::models::jwks_state::JwksState;

pub struct JwtToken {
    pub claims: Claims,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for JwtToken {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let token = request.headers()
            .get_one("Authorization")
            .and_then(|auth| auth.strip_prefix("Bearer "));

        if let Some(token) = token {
            let state = request.rocket().state::<JwksState>().unwrap();
            let jwks = state.jwks.read().await;
            match validate_token(token, &jwks, &state.audiences).await {
                Ok(claims) => Outcome::Success(JwtToken { claims }),
                Err(_) => Outcome::Error((Status::Unauthorized, ())),
            }
        } else {
            Outcome::Error((Status::Unauthorized, ()))
        }
    }
}