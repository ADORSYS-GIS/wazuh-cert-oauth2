use tokio::process::Command;
use wazuh_cert_oauth2_model::models::errors::{AppError, AppResult};

/// Run a sed command to replace the content of a file.
pub async fn sed_command(content: &str, file_path: &str) -> AppResult<()> {
    let status = if cfg!(target_os = "macos") {
        Command::new("gsed")
            .arg("-i")
            .arg(content)
            .arg(file_path)
            .status()
            .await
    } else {
        Command::new("sed")
            .arg("-i")
            .arg(content)
            .arg(file_path)
            .status()
            .await
    };

    match status {
        Ok(s) => {
            if !s.success() {
                let program = if cfg!(target_os = "macos") {
                    "gsed"
                } else {
                    "sed"
                };

                return Err(AppError::CommandFailed {
                    program: program.into(),
                    code: s.code(),
                });
            }
        }
        Err(e) => {
            let program = if cfg!(target_os = "macos") {
                "gsed"
            } else {
                "sed"
            };
            return Err(AppError::CommandSpawn {
                program: program.into(),
                err: e.to_string(),
            });
        }
    }

    Ok(())
}
