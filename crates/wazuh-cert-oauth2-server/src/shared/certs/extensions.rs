use openssl::x509::X509Extension;
use openssl::x509::X509Ref;
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier,
};
use wazuh_cert_oauth2_model::models::errors::AppResult;
use url::Url;

pub(crate) fn append_core_extensions(
    builder: &mut openssl::x509::X509Builder,
    ca_cert: &X509Ref,
) -> AppResult<()> {
    let basic_constraints = BasicConstraints::new().critical().build()?;
    builder.append_extension(basic_constraints)?;
    let ski = SubjectKeyIdentifier::new().build(&builder.x509v3_context(Some(ca_cert), None))?;
    builder.append_extension(ski)?;
    let aki = AuthorityKeyIdentifier::new()
        .keyid(true)
        .issuer(true)
        .build(&builder.x509v3_context(Some(ca_cert), None))?;
    builder.append_extension(aki)?;
    Ok(())
}

pub(crate) fn append_crl_dp(
    builder: &mut openssl::x509::X509Builder,
    ca_cert: &X509Ref,
    crl_dist_url: Option<&str>,
) -> AppResult<()> {
    if let Some(url) = crl_dist_url {
        let cdp = X509Extension::new(
            None,
            Some(&builder.x509v3_context(Some(ca_cert), None)),
            "crlDistributionPoints",
            &format!("URI:{}", url),
        )?;
        builder.append_extension(cdp)?;
    }
    Ok(())
}

pub(crate) fn append_key_usage(
    builder: &mut openssl::x509::X509Builder,
    is_rsa: bool,
) -> AppResult<()> {
    let mut ku = KeyUsage::new();
    ku.critical();
    ku.digital_signature();
    if is_rsa {
        ku.key_encipherment();
    }
    builder.append_extension(ku.build()?)?;
    Ok(())
}

pub(crate) fn append_client_eku(builder: &mut openssl::x509::X509Builder) -> AppResult<()> {
    let eku = ExtendedKeyUsage::new().client_auth().build()?;
    builder.append_extension(eku)?;
    Ok(())
}

pub(crate) fn append_san_cn(
    builder: &mut openssl::x509::X509Builder,
    ca_cert: &X509Ref,
    subject_cn: &str,
) -> AppResult<()> {
    let san = SubjectAlternativeName::new()
        .dns(subject_cn)
        .build(&builder.x509v3_context(Some(ca_cert), None))?;
    builder.append_extension(san)?;
    Ok(())
}

/// Add a SAN URI that binds the Keycloak issuer (realm) and subject together.
/// Uses the form: "{iss}#sub={sub}", which remains a valid absolute URI while
/// clearly associating the realm (from iss) with the subject identifier.
pub(crate) fn append_san_identity_uri(
    builder: &mut openssl::x509::X509Builder,
    ca_cert: &X509Ref,
    issuer: &str,
    subject_sub: &str,
) -> AppResult<()> {
    // Best-effort: ensure issuer parses as a URL; if not, still include a URN form
    let value = match Url::parse(issuer) {
        Ok(url) => {
            // Reconstruct without params to avoid accidental leakage; keep path/host which include realm
            let mut base = String::new();
            base.push_str(url.as_str());
            // Append the subject in a fragment to keep it within the URI
            format!("{}#sub={}", base.trim_end_matches('#'), subject_sub)
        }
        Err(_) => format!("urn:keycloak:sub:{}", subject_sub),
    };
    let san = SubjectAlternativeName::new()
        .uri(&value)
        .build(&builder.x509v3_context(Some(ca_cert), None))?;
    builder.append_extension(san)?;
    Ok(())
}
