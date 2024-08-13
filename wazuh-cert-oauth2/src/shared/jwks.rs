use anyhow::Result;
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use reqwest::Client;
use crate::models::claims::Claims;

pub async fn fetch_jwks(jwks_url: &str) -> Result<jsonwebtoken::jwk::JwkSet> {
    let jwks = Client::new()
        .get(jwks_url)
        .send()
        .await?
        .json()
        .await?;

    Ok(jwks)
}

pub async fn validate_token(
    token: &str,
    jwks: &jsonwebtoken::jwk::JwkSet,
    audiences: &Vec<String>,
) -> Result<Claims, jsonwebtoken::errors::Error> {
    let header = decode_header(token)?;
    debug!("decoded header: {:?}", header);
    let kid = header.kid.ok_or(jsonwebtoken::errors::ErrorKind::InvalidKeyFormat)?;

    debug!("looking up key with kid: {}", kid);
    let jwk = jwks.find(&kid).ok_or(jsonwebtoken::errors::ErrorKind::InvalidKeyFormat)?;

    debug!("found key");
    let key = DecodingKey::from_jwk(jwk)?;

    debug!("validating token");
    let mut validation = Validation::new(header.alg);
    validation.set_audience(audiences);

    debug!("decoding token");
    let result = decode::<Claims>(token, &key, &validation);
    if let Ok(decoded_token) = result {
        debug!("decoded token");
        Ok(decoded_token.claims)
    } else if let Err(err) = result {
        eprintln!("{}", err);
        Err(jsonwebtoken::errors::ErrorKind::InvalidToken.into())
    } else {
        Err(jsonwebtoken::errors::ErrorKind::InvalidToken.into())
    }

}