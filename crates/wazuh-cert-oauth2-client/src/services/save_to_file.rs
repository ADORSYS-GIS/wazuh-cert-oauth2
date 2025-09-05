use anyhow::Result;
use std::path::Path;
use tokio::fs::{create_dir_all, write, OpenOptions};
use tokio::io::AsyncWriteExt;

/// Save the certificate (and optional chain) and the private key to files.
pub async fn save_cert_and_key(
    cert_file: &str,
    key_file: &str,
    certificate_pem: &str,
    private_key_pem: &str,
    ca_chain_pem: Option<&str>,
) -> Result<()> {
    create_parent_dir_if_not_exists(cert_file).await?;
    create_parent_dir_if_not_exists(key_file).await?;

    let mut full_cert = String::from(certificate_pem);
    if let Some(chain) = ca_chain_pem {
        full_cert.push('\n');
        full_cert.push_str(chain);
    }

    log::info!("Writing certificate to file: {:?}", cert_file);
    write(cert_file, full_cert).await?;

    log::info!("Writing private key to file: {:?}", key_file);
    // Create with 0600 on Unix; best-effort on other platforms
    let mut std_opts = OpenOptions::new();
    std_opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        std_opts.mode(0o600);
    }
    let mut file = std_opts.open(key_file).await?;
    file.write_all(private_key_pem.as_bytes()).await?;

    Ok(())
}

/// Ensure the directory for the given file path exists.
async fn create_parent_dir_if_not_exists(file_path: &str) -> Result<()> {
    let parent_dir = Path::new(file_path).parent().unwrap();
    log::info!("Creating parent directory: {:?}", parent_dir);
    create_dir_all(parent_dir).await?;
    Ok(())
}
