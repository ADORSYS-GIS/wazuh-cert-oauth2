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
