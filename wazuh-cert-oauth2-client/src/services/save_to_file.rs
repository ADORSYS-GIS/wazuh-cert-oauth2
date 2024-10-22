use anyhow::Result;
use tokio::fs::write;
use std::path::Path;
use tokio::fs::create_dir_all;

use wazuh_cert_oauth2_model::models::user_key::UserKey;

/// Save the keys to the specified files.
pub async fn save_keys(public_key_file: &str, private_key_file: &str, keys: &UserKey) -> Result<()> {
    // Ensure the key parent directory exists
    create_parent_dir_if_not_exists(public_key_file).await?;
    create_parent_dir_if_not_exists(private_key_file).await?;

    // Write the keys to the specified files
    log::info!("Writing public key to file: {:?}", public_key_file);
    write(public_key_file, &keys.public_key).await?;

    // Write the private key to the specified file
    log::info!("Writing private key to file: {:?}", private_key_file);
    write(private_key_file, &keys.private_key).await?;

    Ok(())
}

async fn create_parent_dir_if_not_exists(file_path: &str) -> Result<()> {
    let parent_dir = Path::new(file_path).parent().unwrap();
    log::info!("Creating parent directory: {:?}", parent_dir);
    create_dir_all(parent_dir).await?;
    Ok(())
}