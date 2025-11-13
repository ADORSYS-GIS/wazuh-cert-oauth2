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
