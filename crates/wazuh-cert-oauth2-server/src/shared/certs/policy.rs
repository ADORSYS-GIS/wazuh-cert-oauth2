use openssl::nid::Nid;
use openssl::pkey::Id as PKeyId;
use openssl::pkey::PKey;
use wazuh_cert_oauth2_model::models::errors::{AppError, AppResult};

pub(crate) fn enforce_key_policy(pkey: &PKey<openssl::pkey::Public>) -> AppResult<()> {
    match pkey.id() {
        PKeyId::RSA => {
            let rsa = pkey.rsa()?;
            let bits = (rsa.size() as usize) * 8;
            if bits < 2048 {
                return Err(AppError::KeyPolicyRsaTooSmall { bits });
            }
        }
        PKeyId::EC => {
            let ec = pkey.ec_key()?;
            let nid = ec
                .group()
                .curve_name()
                .ok_or(AppError::KeyPolicyUnknownEcCurve)?;
            if nid != Nid::X9_62_PRIME256V1 {
                return Err(AppError::KeyPolicyUnsupportedEcCurve {
                    nid: format!("{:?}", nid),
                });
            }
        }
        other => {
            return Err(AppError::KeyPolicyUnsupportedKeyType {
                key_type: format!("{:?}", other),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::enforce_key_policy;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use wazuh_cert_oauth2_model::models::errors::AppError;

    fn to_public_key(private: PKey<openssl::pkey::Private>) -> PKey<openssl::pkey::Public> {
        let pem = private
            .public_key_to_pem()
            .expect("public pem conversion should work");
        PKey::public_key_from_pem(&pem).expect("public pem parsing should work")
    }

    #[test]
    fn accepts_rsa_2048_keys() {
        let rsa = Rsa::generate(2048).expect("rsa generation should succeed");
        let public = to_public_key(PKey::from_rsa(rsa).expect("pkey conversion should succeed"));
        assert!(enforce_key_policy(&public).is_ok());
    }

    #[test]
    fn rejects_rsa_keys_smaller_than_2048() {
        let rsa = Rsa::generate(1024).expect("rsa generation should succeed");
        let public = to_public_key(PKey::from_rsa(rsa).expect("pkey conversion should succeed"));

        let err = enforce_key_policy(&public).expect_err("policy should reject small rsa");
        assert!(matches!(
            err,
            AppError::KeyPolicyRsaTooSmall { bits } if bits == 1024
        ));
    }

    #[test]
    fn accepts_p256_ec_keys() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
            .expect("p256 group creation should succeed");
        let ec = EcKey::generate(&group).expect("ec key generation should succeed");
        let public = to_public_key(PKey::from_ec_key(ec).expect("pkey conversion should succeed"));
        assert!(enforce_key_policy(&public).is_ok());
    }

    #[test]
    fn rejects_non_p256_ec_keys() {
        let group = EcGroup::from_curve_name(Nid::SECP384R1)
            .expect("p384 group creation should succeed");
        let ec = EcKey::generate(&group).expect("ec key generation should succeed");
        let public = to_public_key(PKey::from_ec_key(ec).expect("pkey conversion should succeed"));

        let err = enforce_key_policy(&public).expect_err("policy should reject p384");
        assert!(matches!(err, AppError::KeyPolicyUnsupportedEcCurve { .. }));
    }
}
