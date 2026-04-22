use serde::Deserialize;

#[derive(Deserialize, Clone, Debug)]
pub struct Claims {
    pub sub: String,
    #[serde(default)]
    pub name: Option<String>,
    pub iss: String,
    pub exp: usize,
    #[serde(default)]
    pub preferred_username: Option<String>,
    // Add other claims as needed
}

impl Claims {
    pub fn get_name(&self) -> Option<String> {
        self.name
            .clone()
            .or_else(|| self.preferred_username.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::Claims;

    fn base_claims() -> Claims {
        Claims {
            sub: "subject-1".to_string(),
            name: None,
            iss: "https://issuer.example/realms/main".to_string(),
            exp: 9_999_999_999,
            preferred_username: None,
        }
    }

    #[test]
    fn get_name_prefers_name_claim() {
        let mut claims = base_claims();
        claims.name = Some("Primary Name".to_string());
        claims.preferred_username = Some("fallback-user".to_string());

        assert_eq!(claims.get_name().as_deref(), Some("Primary Name"));
    }

    #[test]
    fn get_name_falls_back_to_preferred_username() {
        let mut claims = base_claims();
        claims.preferred_username = Some("fallback-user".to_string());

        assert_eq!(claims.get_name().as_deref(), Some("fallback-user"));
    }

    #[test]
    fn get_name_returns_none_when_missing() {
        let claims = base_claims();
        assert_eq!(claims.get_name(), None);
    }
}
