use std::process::Command;

pub fn restart_wazuh() {
    let output = Command::new("cmd")
        .args(&["/C", "net stop WazuhSvc && net start WazuhSvc"])
        .output()
        .expect("Failed to execute command");

    if output.status.success() {
        println!("Wazuh agent restarted successfully on Windows");
    } else {
        eprintln!(
            "Failed to restart Wazuh agent on Windows: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
