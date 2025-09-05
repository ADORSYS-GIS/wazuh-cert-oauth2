use anyhow::{bail, Result};
use tokio::process::Command;
use wazuh_cert_oauth2_model::models::errors::AppError;

/// Stop the Wazuh agent service on Windows.
#[cfg(target_os = "windows")]
pub async fn stop_agent() -> Result<()> {
    let status = Command::new("powershell")
        .arg("-Command")
        .arg("Stop-Service -Name WazuhSvc -Force")
        .status()
        .await;

    match status {
        Ok(s) => {
            if !s.success() {
                bail!(AppError::CommandFailed { program: "powershell".into(), code: s.code() });
            }
        }
        Err(e) => bail!(AppError::CommandSpawn { program: "powershell".into(), err: e.to_string() }),
    }

    Ok(())
}

/// Stop the Wazuh agent on macOS/Linux using wazuh-control.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub async fn stop_agent() -> Result<()> {
    use crate::shared::path::default_path_agent_control;

    let control_bin = default_path_agent_control();
    let status = Command::new(&control_bin).arg("stop").status().await;

    match status {
        Ok(s) => {
            if !s.success() {
                bail!(AppError::CommandFailed { program: control_bin, code: s.code() });
            }
        }
        Err(e) => bail!(AppError::CommandSpawn { program: control_bin, err: e.to_string() }),
    }

    Ok(())
}
