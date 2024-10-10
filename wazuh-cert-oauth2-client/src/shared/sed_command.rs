use anyhow::Result;
use std::process::ExitStatus;
use tokio::process::Command;

/// Run a sed command to replace the content of a file.
pub async fn sed_command(content: &str, file_path: &str) -> Result<ExitStatus> {
    let status = if cfg!(target_os = "macos") {
        Command::new("sed")
            .arg("-i").arg("")
            .arg(&content)
            .arg(&file_path)
            .status()
            .await?
    } else {
        Command::new("sed")
            .arg("-i")
            .arg(&content)
            .arg(&file_path)
            .status()
            .await?
    };

    Ok(status)
}