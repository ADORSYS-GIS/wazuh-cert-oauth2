use anyhow::Result;
use tokio::fs::write;

use wazuh_cert_oauth2_model::models::user_key::UserKey;

/// Save the keys to the specified files.
pub async fn save_keys(public_key_file: &str, private_key_file: &str, keys: &UserKey) -> Result<()> {
    // Write the keys to the specified files
    write(public_key_file, &keys.public_key).await?;

    // Write the private key to the specified file
    write(private_key_file, &keys.private_key).await?;

    Ok(())
}