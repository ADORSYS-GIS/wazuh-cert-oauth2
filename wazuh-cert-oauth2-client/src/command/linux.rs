use std::process::Command;

pub fn restart_wazuh() {
    let output = Command::new("sh")
        .arg("-c")
        .arg("sudo systemctl restart wazuh-agent")
        .output()
        .expect("Failed to execute command");

    if output.status.success() {
        println!("Wazuh agent restarted successfully on Linux");
    } else {
        eprintln!(
            "Failed to restart Wazuh agent on Linux: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
