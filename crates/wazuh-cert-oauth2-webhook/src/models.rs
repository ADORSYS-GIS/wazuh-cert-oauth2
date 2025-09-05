use serde::Serialize;

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
