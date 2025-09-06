use crate::models::claims::Claims;
use crate::models::errors::{AppError, AppResult};
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use tracing::debug;

/// Validate the token using the provided JWKS.
pub async fn validate_token(
    token: &str,
    jwks: &JwkSet,
    audiences: &Option<Vec<String>>,
) -> AppResult<Claims> {
    let header = decode_header(token)?;
    debug!("decoded header: {:?}", header);
    let kid = match header.kid {
        None => {
            return Err(AppError::JwtMissingKid);
        }
        Some(v) => v,
    };

    debug!("looking up key with kid: {}", kid);
    let jwk = match jwks.find(&kid) {
        None => {
            return Err(AppError::JwtKeyNotFound(kid));
        }
        Some(v) => v,
    };

    debug!("found key");
    let key = DecodingKey::from_jwk(jwk)?;

    debug!("validating token");
    let mut validation = Validation::new(header.alg);
    if let Some(audiences) = &audiences {
        validation.set_audience(audiences);
    } else {
        validation.validate_aud = false;
    }

    debug!("decoding token");
    match decode::<Claims>(token, &key, &validation) {
        Ok(decoded_token) => {
            debug!("decoded token");
            Ok(decoded_token.claims)
        }
        Err(e) => {
            debug!("Could not decode the token");
            Err(AppError::JwtError(e))
        }
    }
}
