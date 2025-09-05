use crate::models::claims::Claims;
use crate::models::errors::AppError;
use anyhow::{bail, Result};
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};

/// Validate the token using the provided JWKS.
pub async fn validate_token(
    token: &str,
    jwks: &jsonwebtoken::jwk::JwkSet,
    audiences: &Vec<String>,
) -> Result<Claims> {
    let header = decode_header(token)?;
    debug!("decoded header: {:?}", header);
    let kid = match header.kid {
        None => {
            bail!(AppError::JwtMissingKid);
        }
        Some(v) => v,
    };

    debug!("looking up key with kid: {}", kid);
    let jwk = match jwks.find(&kid) {
        None => {
            bail!(AppError::JwtKeyNotFound(kid));
        }
        Some(v) => v,
    };

    debug!("found key");
    let key = DecodingKey::from_jwk(jwk)?;

    debug!("validating token");
    let mut validation = Validation::new(header.alg);
    validation.set_audience(audiences);

    debug!("decoding token");
    match decode::<Claims>(token, &key, &validation) {
        Ok(decoded_token) => {
            debug!("decoded token");
            Ok(decoded_token.claims)
        }
        Err(e) => {
            debug!("Could not decode the token");
            bail!(AppError::JwtError(e))
        }
    }
}
