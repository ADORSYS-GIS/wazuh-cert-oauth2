use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};
use wazuh_cert_oauth2_model::models::claims::Claims;
use wazuh_cert_oauth2_model::services::jwks::validate_token;

use crate::models::oidc_state::OidcState;

pub struct JwtToken {
    pub claims: Claims,
}

impl JwtToken {
    pub fn new(claims: Claims) -> JwtToken {
        JwtToken { claims }
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for JwtToken {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let token = request.headers()
            .get_one("Authorization")
            .and_then(|auth| auth.strip_prefix("Bearer "));

        if let Some(token) = token {
            let state = request.rocket().state::<OidcState>().unwrap();
            match state.get_jwks().await {
                Ok(jwks) => match validate_token(token, jwks.as_ref(), &state.audiences).await {
                    Ok(claims) => Outcome::Success(JwtToken::new(claims)),
                    Err(e) => {
                        error!("Could not get claims {}", e);
                        Outcome::Error((Status::Unauthorized, ()))
                    }
                },
                Err(e) => {
                    error!("Could not get JWKS {}", e);
                    Outcome::Error((Status::Unauthorized, ()))
                }
            }
        } else {
            error!("No token found");
            Outcome::Error((Status::Unauthorized, ()))
        }
    }
}
