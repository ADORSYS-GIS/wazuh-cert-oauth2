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

#[cfg(test)]
mod tests {
    use super::validate_token;
    use crate::models::errors::AppError;
    use jsonwebtoken::jwk::JwkSet;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use serde::Serialize;

    #[derive(Serialize)]
    struct TestClaims {
        sub: String,
        iss: String,
        exp: usize,
        name: Option<String>,
        preferred_username: Option<String>,
    }

    fn sample_claims() -> TestClaims {
        TestClaims {
            sub: "subject-1".to_string(),
            iss: "https://issuer.example/realms/test".to_string(),
            exp: 4_102_444_800, // 2100-01-01
            name: Some("Alice".to_string()),
            preferred_username: None,
        }
    }

    #[tokio::test]
    async fn validate_token_fails_when_kid_is_missing() {
        let header = Header::new(Algorithm::HS256);
        let token = encode(
            &header,
            &sample_claims(),
            &EncodingKey::from_secret(b"secret"),
        )
        .expect("token should encode");
        let jwks = JwkSet { keys: vec![] };

        let err = validate_token(&token, &jwks, &None).await.unwrap_err();
        assert!(matches!(err, AppError::JwtMissingKid));
    }

    #[tokio::test]
    async fn validate_token_fails_when_kid_not_found_in_jwks() {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("missing-kid".to_string());
        let token = encode(
            &header,
            &sample_claims(),
            &EncodingKey::from_secret(b"secret"),
        )
        .expect("token should encode");
        let jwks = JwkSet { keys: vec![] };

        let err = validate_token(&token, &jwks, &None).await.unwrap_err();
        assert!(matches!(err, AppError::JwtKeyNotFound(k) if k == "missing-kid"));
    }
}
