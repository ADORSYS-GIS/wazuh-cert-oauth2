use anyhow::Result;
use openssl::x509::X509Extension;
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier,
};
use openssl::x509::X509Ref;

#[inline]
pub(crate) fn append_core_extensions(builder: &mut openssl::x509::X509Builder, ca_cert: &X509Ref) -> Result<()> {
    let basic_constraints = BasicConstraints::new().critical().build()?;
    builder.append_extension(basic_constraints)?;
    let ski = SubjectKeyIdentifier::new().build(&builder.x509v3_context(Some(ca_cert), None))?;
    builder.append_extension(ski)?;
    let aki = AuthorityKeyIdentifier::new().keyid(true).issuer(true).build(&builder.x509v3_context(Some(ca_cert), None))?;
    builder.append_extension(aki)?;
    Ok(())
}

#[inline]
pub(crate) fn append_crl_dp(
    builder: &mut openssl::x509::X509Builder,
    ca_cert: &X509Ref,
    crl_dist_url: Option<&str>,
) -> Result<()> {
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

#[inline]
pub(crate) fn append_key_usage(builder: &mut openssl::x509::X509Builder, is_rsa: bool) -> Result<()> {
    let mut ku = KeyUsage::new();
    ku.critical();
    ku.digital_signature();
    if is_rsa { ku.key_encipherment(); }
    builder.append_extension(ku.build()?)?;
    Ok(())
}

#[inline]
pub(crate) fn append_client_eku(builder: &mut openssl::x509::X509Builder) -> Result<()> {
    let eku = ExtendedKeyUsage::new().client_auth().build()?;
    builder.append_extension(eku)?;
    Ok(())
}

#[inline]
pub(crate) fn append_san_cn(
    builder: &mut openssl::x509::X509Builder,
    ca_cert: &X509Ref,
    subject_cn: &str,
) -> Result<()> {
    let san = SubjectAlternativeName::new().dns(subject_cn).build(&builder.x509v3_context(Some(ca_cert), None))?;
    builder.append_extension(san)?;
    Ok(())
}

