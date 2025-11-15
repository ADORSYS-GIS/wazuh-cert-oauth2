use std::path::Path;
use tokio::fs::{OpenOptions, create_dir_all};
use tokio::io::AsyncWriteExt;
use wazuh_cert_oauth2_model::models::errors::AppResult;

/// Save the certificate (and optional chain) and the private key to files.
pub async fn save_cert_and_key(
    cert_file: &str,
    key_file: &str,
    certificate_pem: &str,
    private_key_pem: &str,
    ca_chain_pem: Option<&str>,
) -> AppResult<()> {
    create_parent_dir_if_not_exists(cert_file).await?;
    create_parent_dir_if_not_exists(key_file).await?;

    let mut full_cert = String::from(certificate_pem);
    if let Some(chain) = ca_chain_pem {
        full_cert.push('\n');
        full_cert.push_str(chain);
    }

    log::info!("Writing certificate to file: {:?}", cert_file);
    write_with_permissions(cert_file, full_cert).await?;

    log::info!("Writing private key to file: {:?}", key_file);
    write_with_permissions(key_file, private_key_pem).await?;

    Ok(())
}

async fn write_with_permissions(
    file_path: impl AsRef<Path>,
    contents: impl AsRef<[u8]>,
) -> AppResult<()> {
    let mut std_opts = OpenOptions::new();
    std_opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        // Create with 0640 on Unix; best-effort on other platforms
        std_opts.mode(0o640);
    }
    let mut file = std_opts.open(file_path).await?;
    file.write_all(contents.as_ref()).await?;

    Ok(())
}

/// Ensure the directory for the given file path exists.
async fn create_parent_dir_if_not_exists(file_path: &str) -> AppResult<()> {
    let parent_dir = Path::new(file_path).parent().unwrap();
    log::info!("Creating parent directory: {:?}", parent_dir);
    create_dir_all(parent_dir).await?;
    Ok(())
}
