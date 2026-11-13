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

/// Restrict a Windows private key to its owner, LocalSystem and Administrators.
///
/// The Wazuh agent service runs as LocalSystem by default and must keep read
/// access, while other local users (for example the inherited `Users` group)
/// must not be able to read the key.
#[cfg(windows)]
fn harden_private_key_acl(path: &Path) -> AppResult<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        SetFileSecurityW,
    };

    // D:P          -> protected DACL (inheritance disabled)
    // (A;;FA;;;SY) -> full control for LocalSystem
    // (A;;FA;;;BA) -> full control for Administrators
    // (A;;FA;;;OW) -> full control for the file owner (Owner Rights)
    const PRIVATE_KEY_SDDL: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)";

    let sddl: Vec<u16> = PRIVATE_KEY_SDDL
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        ) == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }

        let result = SetFileSecurityW(
            wide_path.as_ptr(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor,
        );
        // Capture the error before LocalFree can overwrite it.
        let error = std::io::Error::last_os_error();
        LocalFree(descriptor);

        if result == 0 {
            return Err(error.into());
        }
    }

    Ok(())
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
    #[cfg(not(any(unix, windows)))]
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

    #[cfg(windows)]
    {
        if matches!(kind, FileKind::PrivateKey) {
            harden_private_key_acl(path)?;
        }
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
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::fs;

    fn unique_temp_dir() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos();
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "wazuh-client-save-test-{}-{nanos}-{unique}",
            std::process::id()
        ))
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

    /// On Windows the private key must end up with a protected DACL that only
    /// grants LocalSystem, Administrators and the file owner, and must not be
    /// readable by ordinary users.
    #[cfg(windows)]
    #[tokio::test]
    async fn save_cert_and_key_restricts_private_key_acl_on_windows() {
        use std::process::Command;

        let dir = unique_temp_dir();
        let cert_file = dir.join("sslagent.cert");
        let key_file = dir.join("sslagent.key");

        save_cert_and_key(
            &cert_file.to_string_lossy(),
            &key_file.to_string_lossy(),
            "CERT",
            "KEY",
            &dir.join("ca.pem").to_string_lossy(),
            Some("CA_CHAIN"),
        )
        .await
        .expect("save should succeed");

        // Ask Windows itself, translating identities to stable SIDs so the
        // assertions do not depend on the machine's locale.
        let script = format!(
            "$acl = Get-Acl -LiteralPath '{}'\n\
             [Console]::WriteLine('protected=' + $acl.AreAccessRulesProtected)\n\
             foreach ($ace in $acl.Access) {{ [Console]::WriteLine($ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value) }}",
            key_file.display()
        );
        let output = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .output()
            .expect("powershell should run");
        assert!(
            output.status.success(),
            "Get-Acl failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        let protected = stdout
            .lines()
            .next()
            .expect("first line is the protection state");
        assert_eq!(
            protected, "protected=True",
            "private key DACL must be protected (inheritance disabled), got:\n{stdout}"
        );

        let sids: Vec<&str> = stdout.lines().skip(1).collect();
        // LocalSystem and Administrators must be present.
        for expected in ["S-1-5-18", "S-1-5-32-544"] {
            assert!(
                sids.contains(&expected),
                "expected {expected} on the key ACL, got: {sids:?}"
            );
        }
        // Ordinary users must not be able to read the key.
        for forbidden in ["S-1-5-32-545", "S-1-5-11", "S-1-1-0"] {
            assert!(
                !sids.contains(&forbidden),
                "unexpected {forbidden} on the key ACL: {sids:?}"
            );
        }

        let _ = fs::remove_dir_all(dir).await;
    }
}
