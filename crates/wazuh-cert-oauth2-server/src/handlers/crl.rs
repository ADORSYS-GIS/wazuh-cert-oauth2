use rocket::State;
use rocket::http::{ContentType, Status};
use rocket::request::Request;
use rocket::response::Responder;
use rocket::serde::json::Json;

use crate::handlers::crl_fairing::ExtractedClientEtag;
use crate::models::ca_config::CaProvider;
use crate::shared::crl::CrlState;
use crate::shared::crl::RevocationEntry;
use crate::shared::crl::compute_etag;
use crate::shared::ledger::Ledger;
use openssl::asn1::Asn1Time;
use openssl::x509::X509Crl;
use std::io::Cursor;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time;
use tracing::{debug, error, info};
use wazuh_cert_oauth2_model::models::errors::AppError;

/// Maximum time (seconds) the server holds a long-poll connection open while
/// waiting for the CRL to change.
const LONG_POLL_TIMEOUT_SECS: u64 = 25;

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

/// Either serve the current CRL or respond with `304 Not Modified`.
pub enum CrlOrNotModified {
    Crl(CrlResponse),
    NotModified(String),
}

impl<'r, 'o: 'r> Responder<'r, 'o> for CrlOrNotModified {
    fn respond_to(self, _req: &'r Request<'_>) -> rocket::response::Result<'o> {
        match self {
            Self::Crl(r) => r.respond_to(_req),
            Self::NotModified(etag) => rocket::Response::build()
                .status(Status::NotModified)
                .raw_header("ETag", format!("\"{}\"", etag))
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
    client_etag: ExtractedClientEtag,
) -> Result<CrlOrNotModified, Status> {
    info!("GET /crl/issuing.crl requested");

    let client_etag = &client_etag.0;

    let mut rx = crl.subscribe_rebuild();

    let cached_body = rx.borrow().1.clone();
    let mut bytes: Vec<u8> = match cached_body {
        Some(cached) => {
            debug!("Serving CRL from in-memory cache ({} bytes)", cached.len());
            cached.to_vec()
        }
        None => {
            debug!("No cached CRL; reading from disk");
            match crl.read_crl_file().await {
                Ok(b) => b,
                Err(AppError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
                Err(e) => {
                    error!("Failed to read CRL file: {}", e);
                    return Err(Status::InternalServerError);
                }
            }
        }
    };

    // If missing or expired, rebuild via mpsc and re-read
    if bytes.is_empty() || is_crl_expired(&bytes) {
        info!("CRL missing or expired; triggering on-demand rebuild");
        let (ca_cert, ca_key) = match ca.get().await {
            Ok(v) => v,
            Err(e) => {
                error!("Failed to load CA for CRL rebuild: {}", e);
                return Err(Status::InternalServerError);
            }
        };
        let revs = ledger.revoked_as_revocations().await;
        if let Err(e) = crl.request_rebuild(ca_cert, ca_key, revs).await {
            error!("Failed to rebuild CRL: {}", e);
            return Err(Status::InternalServerError);
        }
        // Read updated state, marking it as seen to avoid a spurious wakeup
        // from our own rebuild when we enter the long-poll loop below.
        bytes = {
            let borrow = rx.borrow_and_update();
            match borrow.1.as_ref() {
                Some(b) => b.to_vec(),
                None => {
                    error!("CRL cache empty after rebuild");
                    return Err(Status::InternalServerError);
                }
            }
        };
    }

    let etag = compute_etag(&bytes);
    debug!("CRL bytes length: {}, ETag: {}", bytes.len(), etag);

    // --- Long-poll negotiation ---
    if !client_etag.is_empty() && *client_etag == etag {
        info!(
            "Client ETag ({}) matches current; entering long-poll ({}s)",
            &etag, LONG_POLL_TIMEOUT_SECS
        );
        let deadline = time::Instant::now() + Duration::from_secs(LONG_POLL_TIMEOUT_SECS);

        loop {
            let remaining = deadline.saturating_duration_since(time::Instant::now());
            if remaining.is_zero() {
                debug!("Long-poll timeout for ETag {}", &etag);
                return Ok(CrlOrNotModified::NotModified(etag));
            }

            match time::timeout(remaining, rx.changed()).await {
                Ok(Ok(())) => {
                    // Channel updated — borrow once and check ETag first.
                    let (new_etag, new_body) = {
                        let borrow = rx.borrow();
                        (borrow.0.clone(), borrow.1.clone())
                    };
                    if new_etag != etag {
                        info!(
                            "CRL changed during long-poll (old={} new={}); serving new body",
                            &etag, &new_etag
                        );
                        let body = match new_body {
                            Some(b) => b.to_vec(),
                            None => {
                                error!("New CRL body is None during long-poll");
                                return Err(Status::InternalServerError);
                            }
                        };
                        return Ok(CrlOrNotModified::Crl(CrlResponse {
                            etag: new_etag,
                            body,
                        }));
                    }
                    // Same ETag (e.g. spool update without CRL change) — keep waiting.
                    debug!("Watch notified but ETag unchanged; continuing long-poll");
                }
                Ok(Err(_)) => {
                    // Watch channel closed — worker died. The notification
                    // mechanism has failed, but the CRL on disk may still be
                    // valid. Read fresh from disk to serve the latest state,
                    // while still alerting the operator via the error log.
                    error!("CRL watch channel closed during long-poll; falling back to disk read");
                    bytes = crl
                        .read_crl_file()
                        .await
                        .map_err(|_| Status::InternalServerError)?;
                    let fresh_etag = compute_etag(&bytes);
                    return if fresh_etag == etag {
                        Ok(CrlOrNotModified::NotModified(etag))
                    } else {
                        Ok(CrlOrNotModified::Crl(CrlResponse {
                            etag: fresh_etag,
                            body: bytes,
                        }))
                    };
                }
                Err(_) => {
                    // Timeout elapsed.
                    debug!("Long-poll timeout for ETag {}", &etag);
                    return Ok(CrlOrNotModified::NotModified(etag));
                }
            }
        }
    }

    // --- No matching ETag or different — serve immediately ---
    Ok(CrlOrNotModified::Crl(CrlResponse { etag, body: bytes }))
}

/// Fetch the current revocation DB as JSON (admin/auth token recommended)
#[get("/revocations")]
pub async fn get_revocations(
    _token: crate::handlers::middle::JwtToken,
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
    use super::*;

    #[test]
    fn expired_crl_detected() {
        // An empty / unparseable CRL should be treated as expired
        assert!(is_crl_expired(&[]));
    }
}
