use openssl::pkey::PKey;
use openssl::x509::{X509, X509Ref, X509Req};
use wazuh_cert_oauth2_model::models::errors::{AppError, AppResult};
use wazuh_cert_oauth2_model::models::sign_csr_request::SignCsrRequest;
use wazuh_cert_oauth2_model::models::signed_cert_response::SignedCertResponse;

use crate::handlers::middle::JwtToken;
use crate::models::ca_config::CaProvider;
use crate::shared::crl::CrlState;
use crate::shared::ledger::Ledger;
use crate::shared::webhook_notifier::WebhookNotifier;
use tracing::info;

use super::{
    append_client_eku, append_core_extensions, append_crl_dp, append_key_usage,
    append_san_cn_and_identity_uri, enforce_key_policy, set_serial_number, set_subject_and_pubkey,
    set_validity_1y, sign_builder,
};

fn extract_realm_from_issuer(iss: &str) -> Option<String> {
    if let Ok(url) = url::Url::parse(iss)
        && let Some(segments) = url.path_segments()
    {
        let parts: Vec<_> = segments.collect();
        for i in 0..parts.len() {
            if parts[i].eq_ignore_ascii_case("realms")
                && let Some(next) = parts.get(i + 1)
                && !next.is_empty()
            {
                return Some(next.to_string());
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
    crl: &CrlState,
    webhook: Option<&WebhookNotifier>,
) -> AppResult<SignedCertResponse> {
    // Validate wazuh_agent_name if provided — it is client-supplied and later
    // interpolated into Wazuh API URLs during eviction. Reject characters that
    // could break URL parsing even though reqwest .query() encodes them, as
    // defense-in-depth against revocation-evasion via crafted agent names.
    if let Some(ref name) = dto.wazuh_agent_name {
        validate_agent_name(name)?;
    }

    let csr = X509Req::from_pem(dto.csr_pem.as_bytes())?;
    let csr_pubkey = csr
        .public_key()
        .map_err(|_| AppError::CsrMissingPublicKey)?;
    let verified = csr.verify(&csr_pubkey)?;
    if !verified {
        return Err(AppError::CsrVerificationFailed);
    }

    let is_admin = claims.is_admin();

    if is_admin {
        info!(sub = %claims.sub, "admin user; skipping single-cert policy");
    } else {
        let old_agent_names = ledger
            .check_and_revoke_active(claims.sub.clone(), dto.overwrite == Some(true))
            .await?;
        if let Some(names) = old_agent_names {
            // Rebuild the CRL immediately
            let (ca_cert, ca_key) = ca.get().await?;
            let revs = ledger.revoked_as_revocations().await;
            crl.request_rebuild(ca_cert, ca_key, revs).await?;
            // Notify the webhook to evict the stale Wazuh agent entries (fire-and-forget)
            if let Some(notifier) = webhook {
                notifier.notify_evict(&claims.sub, names).await;
            }
        }
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
            dto.wazuh_agent_name.clone(),
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
    append_san_cn_and_identity_uri(&mut builder, ca_cert, subject_cn, issuer, subject_cn)?;
    sign_builder(&mut builder, ca_key)?;
    Ok(builder.build())
}

/// Validate that a Wazuh agent name contains only safe characters.
///
/// Wazuh agent names are client-supplied at enrollment and later used in
/// Wazuh API URL queries during eviction. We allow alphanumeric characters,
/// hyphens, underscores, dots, and spaces — covering typical agent naming
/// conventions. This is defense-in-depth alongside reqwest's `.query()`
/// URL-encoding.
fn validate_agent_name(name: &str) -> AppResult<()> {
    if name.is_empty() {
        return Err(AppError::ValidationError(
            "wazuh_agent_name must not be empty".into(),
        ));
    }
    if name.len() > 128 {
        return Err(AppError::ValidationError(
            "wazuh_agent_name must not exceed 128 characters".into(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.' || c == ' ')
    {
        return Err(AppError::ValidationError(format!(
            "wazuh_agent_name contains invalid characters: {name}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{extract_realm_from_issuer, validate_agent_name};

    #[test]
    fn extracts_realm_when_realms_segment_exists() {
        let iss = "https://auth.example/realms/my-realm/protocol/openid-connect/token";
        assert_eq!(extract_realm_from_issuer(iss).as_deref(), Some("my-realm"));
    }

    #[test]
    fn extraction_is_case_insensitive_for_realms_segment() {
        let iss = "https://auth.example/REALMS/CaseRealm";
        assert_eq!(extract_realm_from_issuer(iss).as_deref(), Some("CaseRealm"));
    }

    #[test]
    fn returns_none_for_invalid_or_non_realm_urls() {
        assert_eq!(extract_realm_from_issuer("not-a-url"), None);
        assert_eq!(
            extract_realm_from_issuer("https://auth.example/protocol/openid-connect"),
            None
        );
    }

    #[test]
    fn valid_agent_names_pass_validation() {
        assert!(validate_agent_name("DevOps-SRE-123").is_ok());
        assert!(validate_agent_name("agent_name").is_ok());
        assert!(validate_agent_name("node.example.com").is_ok());
        assert!(validate_agent_name("Web Server 01").is_ok());
    }

    #[test]
    fn empty_agent_name_rejected() {
        assert!(validate_agent_name("").is_err());
    }

    #[test]
    fn agent_name_with_url_breaking_chars_rejected() {
        assert!(validate_agent_name("agent&evil").is_err());
        assert!(validate_agent_name("agent?param").is_err());
        assert!(validate_agent_name("agent#frag").is_err());
        assert!(validate_agent_name("agent/path").is_err());
        assert!(validate_agent_name("agent%20").is_err());
    }

    #[test]
    fn overly_long_agent_name_rejected() {
        let name = "a".repeat(129);
        assert!(validate_agent_name(&name).is_err());
    }
}
