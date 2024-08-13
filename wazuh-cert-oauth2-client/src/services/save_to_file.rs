use anyhow::Result;
use tokio::fs::write;

use wazuh_cert_oauth2_model::models::user_key::UserKey;

pub async fn save_keys(public_key_file: &str, private_key_file: &str, keys: &UserKey) -> Result<()> {
    write(public_key_file, &keys.public_key).await?;
    write(private_key_file, &keys.private_key).await?;
    Ok(())
}