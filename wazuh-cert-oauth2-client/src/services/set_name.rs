use crate::shared::path::{default_path_agent_control, default_path_to_ossec_conf};
use crate::shared::sed_command::sed_command;
use anyhow::Result;
use tokio::process::Command;

/**
Edit the ossef.conf file and add agent_name under client tag.
Then restart the agent to apply the changes.
*/
pub async fn set_name(name: &str) -> Result<()> {
    let machine_id = mid::get(name)?;
    let agent_name = format!("{}-{}", name, machine_id)
        .replace(|c: char| !c.is_alphanumeric(), "-");

    let ossec_conf = default_path_to_ossec_conf();

    let update_cmd = format!(r"s|<agent_name>.*</agent_name>|<agent_name>{}</agent_name>|g", agent_name);
    sed_command(&update_cmd, &ossec_conf).await?;

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