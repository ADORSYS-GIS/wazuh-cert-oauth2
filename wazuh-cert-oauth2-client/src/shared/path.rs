/// Define a function to handle the default cert path
pub fn default_cert_path() -> String {
    let cert_path = default_path_to_ossec();
    format!("{}/etc/sslagent.cert", cert_path)
}

/// Define a function to handle the default key path
pub fn default_key_path() -> String {
    let cert_path = default_path_to_ossec();
    format!("{}/etc/sslagent.key", cert_path)
}

/// Define a function to handle the default path to the agent control
pub fn default_path_agent_control() -> String {
    let ossec_path = default_path_to_ossec();
    format!("{}/bin/wazuh-control", ossec_path)
}

/// Define a function to handle the default path to the ossec.conf file
pub fn default_path_to_ossec_conf() -> String {
    let ossec_path = default_path_to_ossec();
    if cfg!(target_os = "windows") {
        format!(r"{}\ossec.conf", ossec_path)
    } else {
        format!("{}/etc/ossec.conf", ossec_path)
    }
}

/// Define a function to handle the default path to the ossec directory
pub fn default_path_to_ossec() -> &'static str {
    if cfg!(target_os = "macos") {
        "/Library/Ossec"
    } else if cfg!(target_os = "windows") {
        r"C:\Program Files (x86)\ossec-agent"
    } else {
        "/var/ossec"
    }
}