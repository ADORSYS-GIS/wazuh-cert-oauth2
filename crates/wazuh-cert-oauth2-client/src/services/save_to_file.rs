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
    ca_cert_path: &str,
    ca_chain_pem: Option<&str>,
) -> AppResult<()> {
    let cert = String::from(certificate_pem);
    log::info!("Writing certificate to file: {:?}", cert_file);
    write_with_permissions(cert_file, cert).await?;

    log::info!("Writing private key to file: {:?}", key_file);
    write_with_permissions(key_file, private_key_pem).await?;

    if let Some(chain) = ca_chain_pem {
        log::info!("Writing private key to file: {:?}", ca_cert_path);
        write_with_permissions(ca_cert_path, chain).await?;
    }

    Ok(())
}

async fn write_with_permissions(
    file_path: impl AsRef<Path>,
    contents: impl AsRef<[u8]>,
) -> AppResult<()> {
    create_parent_dir_if_not_exists(file_path.as_ref()).await?;

    let mut std_opts = OpenOptions::new();
    std_opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        // Create with 0640 on Unix; best-effort on other platforms
        std_opts.mode(0o644);
    }
    let mut file = std_opts.open(file_path).await?;
    file.write_all(contents.as_ref()).await?;

    Ok(())
}

/// Ensure the directory for the given file path exists.
async fn create_parent_dir_if_not_exists(file_path: impl AsRef<Path>) -> AppResult<()> {
    let parent_dir = Path::new(file_path.as_ref()).parent().unwrap();
    log::info!("Creating parent directory: {:?}", parent_dir);
    create_dir_all(parent_dir).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::save_cert_and_key;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::fs;

    fn unique_temp_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos();
        std::env::temp_dir().join(format!("wazuh-client-save-test-{}", nanos))
    }

    #[tokio::test]
    async fn save_cert_and_key_writes_all_files_when_chain_is_present() {
        let dir = unique_temp_dir();
        let cert_file = dir.join("nested").join("sslagent.cert");
        let key_file = dir.join("nested").join("sslagent.key");
        let ca_file = dir.join("nested").join("ca.pem");

        save_cert_and_key(
            &cert_file.to_string_lossy(),
            &key_file.to_string_lossy(),
            "CERT",
            "KEY",
            &ca_file.to_string_lossy(),
            Some("CA_CHAIN"),
        )
        .await
        .expect("save should succeed");

        assert_eq!(
            fs::read_to_string(&cert_file)
                .await
                .expect("cert should exist"),
            "CERT"
        );
        assert_eq!(
            fs::read_to_string(&key_file)
                .await
                .expect("key should exist"),
            "KEY"
        );
        assert_eq!(
            fs::read_to_string(&ca_file).await.expect("ca should exist"),
            "CA_CHAIN"
        );

        let _ = fs::remove_dir_all(dir).await;
    }

    #[tokio::test]
    async fn save_cert_and_key_does_not_create_ca_file_when_chain_absent() {
        let dir = unique_temp_dir();
        let cert_file = dir.join("sslagent.cert");
        let key_file = dir.join("sslagent.key");
        let ca_file = dir.join("ca.pem");

        save_cert_and_key(
            &cert_file.to_string_lossy(),
            &key_file.to_string_lossy(),
            "CERT_ONLY",
            "KEY_ONLY",
            &ca_file.to_string_lossy(),
            None,
        )
        .await
        .expect("save should succeed");

        assert!(fs::metadata(&cert_file).await.is_ok());
        assert!(fs::metadata(&key_file).await.is_ok());
        assert!(fs::metadata(&ca_file).await.is_err());

        let _ = fs::remove_dir_all(dir).await;
    }
}
