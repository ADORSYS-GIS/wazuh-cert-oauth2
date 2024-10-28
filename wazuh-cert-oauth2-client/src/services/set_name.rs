use crate::shared::path::{default_path_agent_control, default_path_to_ossec_conf};
use crate::shared::sed_command::sed_command;
use anyhow::Result;
use tokio::process::Command;

/// Set the name of the agent.
pub async fn set_name(name: &str) -> Result<()> {
    let machine_id = mid::get(name)?;
    let machine_id = if machine_id.len() > 12 {
        &machine_id[..12]  // Truncate to 12 characters
    } else {
        &machine_id // If within the limit, keep as is
    };

    // Optionally pad the machine_id if it's shorter than 6 characters
    let machine_id = format!("{:0<6}", machine_id); // Pad with '0' to ensure at least 6 characters

    let agent_name = format!("{}-{}", name, machine_id)
        .replace(|c: char| !c.is_alphanumeric(), "-");

    let ossec_conf = default_path_to_ossec_conf();

    let update_cmd = format!(r"s|<agent_name>.*</agent_name>|<agent_name>{}</agent_name>|g", agent_name);
    sed_command(&update_cmd, &ossec_conf).await?;

    if cfg!(target_os = "windows") {
        let status = Command::new("Restart-Service")
            .arg("-Name").arg("wazuh")
            .status().await?;
    
        if !status.success() {
            error!("Failed to restart agent");
            return Ok(());
        }
    } else {
        let control_bin = default_path_agent_control();
        let status = Command::new(control_bin)
            .arg("restart")
            .status().await?;
    
        if !status.success() {
            error!("Failed to restart agent");
            return Ok(());
        }
    }

    Ok(())
}