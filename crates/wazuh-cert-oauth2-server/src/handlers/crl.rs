use rocket::State;
use rocket::http::{ContentType, Status};
use rocket::request::{FromRequest, Outcome, Request};
use rocket::response::Responder;

use crate::handlers::middle::JwtToken;
use crate::models::ca_config::CaProvider;
use crate::shared::crl::CrlState;
use crate::shared::crl::RevocationEntry;
use crate::shared::crl::compute_etag;
use crate::shared::ledger::Ledger;
use openssl::asn1::Asn1Time;
use openssl::x509::X509Crl;
use rocket::serde::json::Json;
use std::io::Cursor;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time;
use tracing::{debug, error, info};
use wazuh_cert_oauth2_model::models::errors::AppError;

const LONG_POLL_TIMEOUT_SECS: u64 = 25;

pub struct IfNoneMatch(pub Option<String>);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for IfNoneMatch {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let etag = req.headers().get_one("If-None-Match").map(|s| {
            s.trim()
                .trim_start_matches("W/")
                .trim_matches('"')
                .to_string()
        });
        Outcome::Success(IfNoneMatch(etag))
    }
}

pub struct CrlResponse {
    etag: String,
    body: Vec<u8>,
}

impl<'r, 'o: 'r> Responder<'r, 'o> for CrlResponse {
    fn respond_to(self, _req: &'r Request<'_>) -> rocket::response::Result<'o> {
        rocket::Response::build()
            .header(ContentType::new("application", "pkix-crl"))
            .raw_header("ETag", format!("\"{}\"", self.etag))
            .raw_header("Cache-Control", "no-cache")
            .sized_body(self.body.len(), Cursor::new(self.body))
            .ok()
    }
}

pub enum CrlOrNotModified {
    Crl(CrlResponse),
    NotModified,
}

impl<'r, 'o: 'r> Responder<'r, 'o> for CrlOrNotModified {
    fn respond_to(self, req: &'r Request<'_>) -> rocket::response::Result<'o> {
        match self {
            CrlOrNotModified::Crl(resp) => resp.respond_to(req),
            CrlOrNotModified::NotModified => rocket::Response::build()
                .status(Status::NotModified)
                .raw_header("Cache-Control", "no-cache")
                .ok(),
        }
    }
}

#[get("/crl/issuing.crl")]
pub async fn get_crl(
    crl: &State<CrlState>,
    ledger: &State<Ledger>,
    ca: &State<CaProvider>,
    if_none_match: IfNoneMatch,
) -> Result<CrlOrNotModified, Status> {
    info!("GET /crl/issuing.crl requested");

    // Try read existing CRL
    let client_etag = if_none_match.0;

    if let Some(ref ctag) = client_etag {
        let mut rx = crl.subscribe_rebuild();
        loop {
            let current = rx.borrow().clone();
            if ctag != &current {
                info!("Client ETag stale; serving fresh CRL");
                break;
            }
            match time::timeout(Duration::from_secs(LONG_POLL_TIMEOUT_SECS), rx.changed()).await {
                Ok(Ok(_)) => continue,
                Ok(Err(_)) => {
                    debug!("Watch channel closed during long-poll; returning 304");
                    return Ok(CrlOrNotModified::NotModified);
                }
                Err(_) => {
                    debug!("Long-poll timeout; returning 304");
                    return Ok(CrlOrNotModified::NotModified);
                }
            }
        }
    }

    let mut bytes = match crl.read_crl_file().await {
        Ok(b) => b,
        Err(AppError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => {
            error!("Failed to read CRL file: {}", e);
            return Err(Status::InternalServerError);
        }
    };

    // If missing or expired, rebuild via mpsc and re-read
    if bytes.is_empty() || is_crl_expired(&bytes) {
        info!("CRL missing or expired; triggering on-demand rebuild");
        let (ca_cert, ca_key) = ca.get().await.map_err(|e| {
            error!("Failed to load CA for CRL rebuild: {}", e);
            Status::InternalServerError
        })?;
        let revs = ledger.revoked_as_revocations().await;
        crl.request_rebuild(ca_cert, ca_key, revs)
            .await
            .map_err(|e| {
                error!("Failed to rebuild CRL: {}", e);
                Status::InternalServerError
            })?;
        // Re-read after successful rebuild
        bytes = crl.read_crl_file().await.map_err(|e| {
            error!("Failed to read CRL file after rebuild: {}", e);
            Status::NotFound
        })?;
    }

    let etag = compute_etag(&bytes);
    debug!("CRL bytes length: {}, ETag: {}", bytes.len(), etag);
    Ok(CrlOrNotModified::Crl(CrlResponse { etag, body: bytes }))
}

/// Fetch the current revocation DB as JSON (admin/auth token recommended)
#[get("/revocations")]
pub async fn get_revocations(
    _token: JwtToken,
    ledger: &State<Ledger>,
) -> Json<Vec<RevocationEntry>> {
    info!("GET /api/revocations requested");
    let revs = ledger.revoked_as_revocations().await;
    debug!("revocations count: {}", revs.len());
    Json(revs)
}

fn is_crl_expired(bytes: &[u8]) -> bool {
    // If parse fails, be conservative and treat as expired
    let crl = match X509Crl::from_der(bytes) {
        Ok(c) => c,
        Err(_) => return true,
    };
    let next = match crl.next_update() {
        Some(n) => n,
        None => return true,
    };
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    // If conversion fails, assume expired to force rebuild
    let now_asn1 = match Asn1Time::from_unix(now_unix) {
        Ok(t) => t,
        Err(_) => return true,
    };
    // Consider expired if nextUpdate <= now
    // Use ordering if available; fall back to not-expired on panic
    next <= now_asn1.as_ref()
}

#[cfg(test)]
mod tests {
    fn strip_etag(raw: &str) -> Option<String> {
        raw.trim()
            .trim_start_matches("W/")
            .trim_matches('"')
            .to_string()
            .into()
    }

    #[test]
    fn strips_quoted_etag() {
        let input = "\"abc123def456\"";
        assert_eq!(strip_etag(input), Some("abc123def456".to_string()));
    }

    #[test]
    fn strips_weak_validator_prefix() {
        let input = "W/\"abc123def456\"";
        assert_eq!(strip_etag(input), Some("abc123def456".to_string()));
    }

    #[test]
    fn passes_through_unquoted_etag() {
        let input = "abc123def456";
        assert_eq!(strip_etag(input), Some("abc123def456".to_string()));
    }

    #[test]
    fn handles_whitespace() {
        let input = "  \"abc123\"  ";
        assert_eq!(strip_etag(input), Some("abc123".to_string()));
    }
}
