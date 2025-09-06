use openssl::pkey::PKey;
use openssl::x509::{X509Ref, X509Req, X509};
use wazuh_cert_oauth2_model::models::errors::{AppError, AppResult};
use wazuh_cert_oauth2_model::models::sign_csr_request::SignCsrRequest;
use wazuh_cert_oauth2_model::models::signed_cert_response::SignedCertResponse;

use crate::handlers::middle::JwtToken;
use crate::models::ca_config::CaProvider;
use crate::shared::ledger::Ledger;

use super::{
    append_client_eku, append_core_extensions, append_crl_dp, append_key_usage, append_san_cn,
    append_san_identity_uri, enforce_key_policy, set_serial_number, set_subject_and_pubkey,
    set_validity_1y, sign_builder,
};

fn extract_realm_from_issuer(iss: &str) -> Option<String> {
    if let Ok(url) = url::Url::parse(iss) {
        if let Some(segments) = url.path_segments() {
            let parts: Vec<_> = segments.collect();
            for i in 0..parts.len() {
                if parts[i].eq_ignore_ascii_case("realms") {
                    if let Some(next) = parts.get(i + 1) {
                        if !next.is_empty() {
                            return Some(next.to_string());
                        }
                    }
                }
            }
        }
    }

    None
}

/// Sign a client-provided CSR with the issuing CA; never generate or return private keys
pub async fn sign_csr(
    dto: SignCsrRequest,
    JwtToken { claims }: JwtToken,
    ca: &CaProvider,
    ledger: &Ledger,
) -> AppResult<SignedCertResponse> {
    let csr = X509Req::from_pem(dto.csr_pem.as_bytes())?;
    let csr_pubkey = csr
        .public_key()
        .map_err(|_| AppError::CsrMissingPublicKey)?;
    let verified = csr.verify(&csr_pubkey)?;
    if !verified {
        return Err(AppError::CsrVerificationFailed);
    }

    enforce_key_policy(&csr_pubkey)?;
    let (ca_cert, ca_key) = ca.get().await?;
    let cert = sign_csr_with_ca(
        &csr,
        &ca_cert,
        &ca_key,
        &claims.sub,
        &claims.iss,
        ca.crl_dist_url(),
    )?;
    let serial_hex = cert.serial_number().to_bn()?.to_hex_str()?.to_string();
    let realm = extract_realm_from_issuer(&claims.iss);
    ledger
        .record_issued(
            claims.sub.clone(),
            serial_hex,
            Some(claims.iss.clone()),
            realm,
        )
        .await?;
    let certificate_pem = String::from_utf8(cert.to_pem()?)?;
    let ca_cert_pem = String::from_utf8(ca_cert.to_pem()?)?;

    Ok(SignedCertResponse {
        certificate_pem,
        ca_cert_pem,
    })
}

/// Sign the CSR with the CA to create a certificate, enforcing EKU/KU/SKI and subject
fn sign_csr_with_ca(
    csr: &X509Req,
    ca_cert: &X509Ref,
    ca_key: &PKey<openssl::pkey::Private>,
    subject_cn: &str,
    issuer: &str,
    crl_dist_url: Option<&str>,
) -> AppResult<X509> {
    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    let is_rsa = set_subject_and_pubkey(&mut builder, csr, ca_cert, subject_cn)?;
    set_serial_number(&mut builder)?;
    set_validity_1y(&mut builder)?;
    append_core_extensions(&mut builder, ca_cert)?;
    append_crl_dp(&mut builder, ca_cert, crl_dist_url)?;
    append_key_usage(&mut builder, is_rsa)?;
    append_client_eku(&mut builder)?;
    append_san_cn(&mut builder, ca_cert, subject_cn)?;
    append_san_identity_uri(&mut builder, ca_cert, issuer, subject_cn)?;
    sign_builder(&mut builder, ca_key)?;
    Ok(builder.build())
}
