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
