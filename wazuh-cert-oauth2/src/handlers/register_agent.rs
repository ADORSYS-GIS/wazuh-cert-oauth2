use rocket::serde::json::Json;
use wazuh_cert_oauth2_model::models::register_agent_dto::RegisterAgentDto;
use wazuh_cert_oauth2_model::models::user_key::UserKey;
use crate::handlers::middle::JwtToken;
use crate::shared::certs::gen_cert;

/// Register a new agent
/// This is done by creating a new key-pair for this agent using the CA
/// and returning both the public and private keys to the caller
#[post("/register-agent", format = "application/json", data = "<dto>")]
pub async fn register_agent(dto: Json<RegisterAgentDto>, token: JwtToken) -> Json<UserKey> {
    let sd = gen_cert(dto.into_inner(), token)
        .expect("Failed to generate certificate");
    Json(sd)
}
