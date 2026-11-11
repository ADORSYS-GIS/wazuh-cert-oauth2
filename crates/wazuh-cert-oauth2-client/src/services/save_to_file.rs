#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tokio::fs::{OpenOptions, create_dir_all};
use tokio::io::AsyncWriteExt;
use wazuh_cert_oauth2_model::models::errors::AppResult;

/// Whether a file holds a certificate (public) or a private key (secret).
#[derive(Clone, Copy)]
enum FileKind {
    Certificate,
    PrivateKey,
}

impl FileKind {
    /// Permissions to apply on Unix. Private keys must never be readable by
    /// group or other users.
    #[cfg(unix)]
    fn unix_mode(self) -> u32 {
        match self {
            Self::Certificate => 0o644,
            Self::PrivateKey => 0o600,
        }
    }
}

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
    write_with_permissions(cert_file, cert, FileKind::Certificate).await?;

    log::info!("Writing private key to file: {:?}", key_file);
    write_with_permissions(key_file, private_key_pem, FileKind::PrivateKey).await?;

    if let Some(chain) = ca_chain_pem {
        log::info!("Writing CA chain to file: {:?}", ca_cert_path);
        write_with_permissions(ca_cert_path, chain, FileKind::Certificate).await?;
    }

    Ok(())
}

async fn write_with_permissions(
    file_path: impl AsRef<Path>,
    contents: impl AsRef<[u8]>,
    kind: FileKind,
) -> AppResult<()> {
    #[cfg(not(unix))]
    let _ = kind;

    let path = file_path.as_ref();
    create_parent_dir_if_not_exists(path).await?;

    let mut std_opts = OpenOptions::new();
    std_opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        std_opts.mode(kind.unix_mode());
    }
    let mut file = std_opts.open(path).await?;
    file.write_all(contents.as_ref()).await?;

    #[cfg(unix)]
    {
        // `OpenOptions::mode` only applies when the file is created. Enforce the
        // policy on pre-existing files too, so a previously world-readable key
        // is tightened on the next write.
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(kind.unix_mode())).await?;
    }

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

    #[cfg(unix)]
    #[tokio::test]
    async fn save_cert_and_key_restricts_private_key_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = unique_temp_dir();
        let cert_file = dir.join("sslagent.cert");
        let key_file = dir.join("sslagent.key");
        let ca_file = dir.join("ca.pem");

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

        let mode = |path: &PathBuf| {
            std::fs::metadata(path)
                .expect("file should exist")
                .permissions()
                .mode()
                & 0o777
        };

        assert_eq!(
            mode(&key_file),
            0o600,
            "private key must not be readable by others"
        );
        assert_eq!(mode(&cert_file), 0o644);
        assert_eq!(mode(&ca_file), 0o644);

        let _ = fs::remove_dir_all(dir).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn save_cert_and_key_tightens_existing_private_key_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = unique_temp_dir();
        let cert_file = dir.join("sslagent.cert");
        let key_file = dir.join("sslagent.key");
        let ca_file = dir.join("ca.pem");

        fs::create_dir_all(&dir).await.expect("create dir");
        fs::write(&key_file, "OLD_KEY").await.expect("write key");
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o644))
            .expect("chmod key");

        save_cert_and_key(
            &cert_file.to_string_lossy(),
            &key_file.to_string_lossy(),
            "CERT",
            "KEY",
            &ca_file.to_string_lossy(),
            None,
        )
        .await
        .expect("save should succeed");

        let mode = std::fs::metadata(&key_file)
            .expect("key should exist")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "an existing world-readable key must be tightened"
        );

        let _ = fs::remove_dir_all(dir).await;
    }
}
