use std::path::{Path, PathBuf};

/// Define a function to handle the default cert path
pub fn default_server_ca_cert_path() -> String {
    let cert_path = default_path_to_ossec();
    let path_buf = cert_path.join("etc").join("ca_cert.pem");
    path_buf.display().to_string()
}

/// Define a function to handle the default cert path
pub fn default_cert_path() -> String {
    let cert_path = default_path_to_ossec();
    let path_buf = cert_path.join("etc").join("sslagent.cert");
    path_buf.display().to_string()
}

/// Define a function to handle the default key path
pub fn default_key_path() -> String {
    let cert_path = default_path_to_ossec();
    let path_buf = cert_path.join("etc").join("sslagent.key");
    path_buf.display().to_string()
}

/// Define a function to handle the default agent control path
pub fn default_path_agent_control() -> String {
    let ossec_path = default_path_to_ossec();
    let path_buf = ossec_path.join("bin").join("wazuh-control");
    path_buf.display().to_string()
}

/// Define a function to handle the default path to ossec.conf
pub fn default_path_to_ossec_conf() -> String {
    let ossec_path = default_path_to_ossec();
    let path_buf = if cfg!(target_os = "windows") {
        ossec_path.join("ossec.conf")
    } else {
        ossec_path.join("etc").join("ossec.conf")
    };
    path_buf.display().to_string()
}

/// Define a function to handle the default path to ossec
pub fn default_path_to_ossec() -> PathBuf {
    let base_path = if cfg!(target_os = "macos") {
        "/Library/Ossec"
    } else if cfg!(target_os = "windows") {
        r"C:\Program Files (x86)\ossec-agent"
    } else {
        "/var/ossec"
    };

    Path::new(base_path).to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::{
        default_cert_path, default_key_path, default_path_agent_control, default_path_to_ossec,
        default_path_to_ossec_conf, default_server_ca_cert_path,
    };

    fn normalize(p: String) -> String {
        p.replace('\\', "/")
    }

    #[test]
    fn default_cert_key_and_ca_paths_are_under_ossec_etc() {
        let base = normalize(default_path_to_ossec().display().to_string());
        let cert = normalize(default_cert_path());
        let key = normalize(default_key_path());
        let ca = normalize(default_server_ca_cert_path());

        assert!(cert.starts_with(&base));
        assert!(key.starts_with(&base));
        assert!(ca.starts_with(&base));
        assert!(cert.ends_with("/etc/sslagent.cert"));
        assert!(key.ends_with("/etc/sslagent.key"));
        assert!(ca.ends_with("/etc/ca_cert.pem"));
    }

    #[test]
    fn default_agent_control_path_points_to_wazuh_control() {
        let control = normalize(default_path_agent_control());
        assert!(control.ends_with("/bin/wazuh-control"));
    }

    #[test]
    fn default_ossec_conf_path_matches_platform_layout() {
        let conf = normalize(default_path_to_ossec_conf());
        if cfg!(target_os = "windows") {
            assert!(conf.ends_with("/ossec.conf"));
            assert!(!conf.contains("/etc/"));
        } else {
            assert!(conf.ends_with("/etc/ossec.conf"));
        }
    }
}
