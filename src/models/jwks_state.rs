use tokio::sync::RwLock;

pub struct JwksState {
    pub(crate) jwks: RwLock<jsonwebtoken::jwk::JwkSet>,
    pub(crate) audiences: Vec<String>,
}
