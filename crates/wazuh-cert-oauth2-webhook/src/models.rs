use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct Health {
    pub status: String,
}

impl Health {
    pub fn ok() -> Self {
        Self {
            status: "OK".into(),
        }
    }
}

#[derive(Deserialize, Debug, Serialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SimpleUserRepresentation {
    pub id: Option<String>,
    pub enabled: bool,
    pub username: Option<String>,
    pub email: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::Health;

    #[test]
    fn health_ok_returns_ok_status() {
        let health = Health::ok();
        assert_eq!(health.status, "OK");
    }
}
