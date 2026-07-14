use rocket::fairing::{Fairing, Info, Kind};
use rocket::request::{self, FromRequest, Request};

/// Caches the `If-None-Match` header from `GET /crl/issuing.crl` as
/// [`ExtractedClientEtag`] for the request.
///
/// Only reads requests; response handling is done by the handler.
pub struct CrlEtagFairing;

/// Client ETag cached per request.
///
/// Implements [`FromRequest`] for handler access. Empty if absent.
pub struct ExtractedClientEtag(pub String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ExtractedClientEtag {
    type Error = std::convert::Infallible;

    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        // Use the cached ETag, or an empty one if the fairing didn't set it.
        let cached = req.local_cache(|| ExtractedClientEtag(String::new()));
        request::Outcome::Success(ExtractedClientEtag(cached.0.clone()))
    }
}

/// Path we intercept in `on_request` to avoid header parsing on unrelated routes.
const CRL_PATH: &str = "/crl/issuing.crl";

/// Strips surrounding double-quotes and the weak validator prefix `W/` from an ETag header value.
pub(crate) fn strip_etag(raw: &str) -> &str {
    raw.trim().trim_start_matches("W/").trim_matches('"')
}

#[rocket::async_trait]
impl Fairing for CrlEtagFairing {
    fn info(&self) -> Info {
        Info {
            name: "CRL ETag",
            kind: Kind::Request,
        }
    }

    async fn on_request(&self, req: &mut Request<'_>, _data: &mut rocket::Data<'_>) {
        // Only intercept GET /crl/issuing.crl
        if req.method() != rocket::http::Method::Get || req.uri().path().as_str() != CRL_PATH {
            return;
        }

        let client_etag = match req.headers().get_one("If-None-Match") {
            Some(raw) => strip_etag(raw).to_string(),
            None => return, // no ETag → handler will serve the full CRL
        };

        // `local_cache` only runs the closure on first access per request.
        // The handler reads this back via the `FromRequest` impl on `ExtractedClientEtag`.
        req.local_cache(|| ExtractedClientEtag(client_etag));
    }
}

#[cfg(test)]
mod tests {
    use super::strip_etag;

    /// Strips surrounding double-quotes from a raw ETag header value.
    #[test]
    fn strips_quoted_etag() {
        let raw = "\"abc123\"";
        assert_eq!(strip_etag(raw), "abc123");
    }

    /// Strips the weak validator prefix `W/` before removing quotes.
    #[test]
    fn strips_weak_validator_prefix() {
        let raw = "W/\"abc123\"";
        assert_eq!(strip_etag(raw), "abc123");
    }

    /// Handles leading/trailing whitespace around ETag values.
    #[test]
    fn handles_whitespace() {
        let raw = "  \"abc123\"  ";
        assert_eq!(strip_etag(raw), "abc123");
    }

    /// Bare (unquoted) ETag values pass through unchanged.
    #[test]
    fn bare_etag_passthrough() {
        let raw = "abc123";
        assert_eq!(strip_etag(raw), "abc123");
    }
}
