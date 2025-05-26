use anyhow::Result;
use tokio::process::Command;

#[cfg(target_os = "windows")]
pub async fn restart_agent() -> Result<()> {
    let status = Command::new("powershell")
        .arg("-Command")
        .arg("Restart-Service -Name WazuhSvc -Force")
        .status().await?;

    if !status.success() {
        error!("Failed to restart agent");
        return Ok(());
    }

    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub async fn restart_agent() -> Result<()> {
    use crate::shared::path::default_path_agent_control;

    let control_bin = default_path_agent_control();
    let status = Command::new(control_bin)
        .arg("restart")
        .status().await?;

    if !status.success() {
        error!("Failed to restart agent");
        return Ok(());
    }

    Ok(())
}
