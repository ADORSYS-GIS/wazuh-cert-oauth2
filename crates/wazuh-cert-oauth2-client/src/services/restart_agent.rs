use tokio::process::Command;
use wazuh_cert_oauth2_model::models::errors::{AppError, AppResult};

/// Restart the Wazuh agent service on Windows.
#[cfg(target_os = "windows")]
pub async fn restart_agent() -> AppResult<()> {
    let status = Command::new("powershell")
        .arg("-Command")
        .arg("Restart-Service -Name WazuhSvc -Force")
        .status()
        .await;

    match status {
        Ok(s) => {
            if !s.success() {
                return Err(AppError::CommandFailed {
                    program: "powershell".into(),
                    code: s.code(),
                });
            }
        }
        Err(e) => {
            return Err(AppError::CommandSpawn {
                program: "powershell".into(),
                err: e.to_string(),
            });
        }
    }

    Ok(())
}

/// Restart the Wazuh agent on macOS/Linux using wazuh-control.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub async fn restart_agent() -> AppResult<()> {
    use crate::shared::path::default_path_agent_control;

    let control_bin = default_path_agent_control();
    let status = Command::new(&control_bin).arg("restart").status().await;

    match status {
        Ok(s) => {
            if !s.success() {
                return Err(AppError::CommandFailed {
                    program: control_bin,
                    code: s.code(),
                });
            }
        }
        Err(e) => {
            return Err(AppError::CommandSpawn {
                program: control_bin,
                err: e.to_string(),
            });
        }
    }

    Ok(())
}
