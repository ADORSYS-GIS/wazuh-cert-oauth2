use serde::Serialize;

#[derive(Serialize)]
pub struct Health {
    pub status: String,
}

impl Health {
    pub fn new() -> Health {
        Health {
            status: "OK".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Health;

    #[test]
    fn health_new_sets_ok_status() {
        let health = Health::new();
        assert_eq!(health.status, "OK");
    }
}
