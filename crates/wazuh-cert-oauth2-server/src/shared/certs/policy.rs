use anyhow::{Result, bail};
use openssl::nid::Nid;
use openssl::pkey::Id as PKeyId;
use openssl::pkey::PKey;
use wazuh_cert_oauth2_model::models::errors::AppError;

pub(crate) fn enforce_key_policy(pkey: &PKey<openssl::pkey::Public>) -> Result<()> {
    match pkey.id() {
        PKeyId::RSA => {
            let rsa = pkey.rsa()?;
            let bits = (rsa.size() as usize) * 8;
            if bits < 2048 { bail!(AppError::KeyPolicyRsaTooSmall { bits }); }
        }
        PKeyId::EC => {
            let ec = pkey.ec_key()?;
            let nid = ec.group().curve_name().ok_or_else(|| anyhow::anyhow!(AppError::KeyPolicyUnknownEcCurve))?;
            if nid != Nid::X9_62_PRIME256V1 { bail!(AppError::KeyPolicyUnsupportedEcCurve { nid: format!("{:?}", nid) }); }
        }
        other => { bail!(AppError::KeyPolicyUnsupportedKeyType { key_type: format!("{:?}", other) }); }
    }
    Ok(())
}

