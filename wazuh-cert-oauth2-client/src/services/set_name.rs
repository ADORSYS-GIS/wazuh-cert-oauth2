use crate::shared::path::{default_path_to_ossec_conf};
use crate::shared::sed_command::sed_command;
use anyhow::Result;
use tokio::process::Command;

/// Set the name of the agent.
pub async fn set_name(name: &str) -> Result<()> {
    let name = diacritics::remove_diacritics(name);
    let long_machine_id = if let Ok(machine_id) = mid::get(&name) {
        info!("Machine ID: {}", machine_id);
        machine_id
    } else {
        info!("Failed to get machine ID, generating random ID");
        let r = rand::random::<u64>();
        format!("{:12}", r) // Generate a random 6 character string
    };

    info!("Long machine ID: {}", long_machine_id);
    let small_machine_id = if long_machine_id.len() > 6 {
        &long_machine_id[..6]
    } else if long_machine_id.len() < 6 {
        &format!("{:0<6}", long_machine_id)
    } else {
        &long_machine_id
    };

    info!("Small machine ID: {}", small_machine_id);
    let agent_name = format!("{}-{}", &name, small_machine_id)
        .replace(|c: char| !c.is_ascii_alphanumeric(), "-");

    let ossec_conf = default_path_to_ossec_conf();
    info!("Updating agent name to {} in {}", agent_name, ossec_conf);

    let update_cmd = format!(r"s|<agent_name>.*</agent_name>|<agent_name>{}</agent_name>|g", agent_name);
    sed_command(&update_cmd, &ossec_conf).await?;

    info!("Agent name updated to {}", agent_name);
    restart_agent().await?;
    Ok(())
}


#[cfg(target_os = "windows")]
async fn restart_agent() -> Result<()> {
    let status = Command::new("Restart-Service")
        .arg("-Name")
        .arg("WazuhSvc")
        .status().await?;

    if !status.success() {
        error!("Failed to restart agent");
        return Ok(());
    }

    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
async fn restart_agent() -> Result<()> {
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