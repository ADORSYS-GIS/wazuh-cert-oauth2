use crate::shared::path::default_path_to_ossec_conf;
use crate::shared::sed_command::sed_command;
use wazuh_cert_oauth2_model::models::errors::AppResult;

/// Set the name of the agent.
pub async fn set_name(agent_name: &str) -> AppResult<()> {
    info!("Setting agent name to {}", agent_name);
    let ossec_conf = default_path_to_ossec_conf();

    let update_cmd = format!(
        r"s|<agent_name>.*</agent_name>|<agent_name>{}</agent_name>|g",
        agent_name
    );
    sed_command(&update_cmd, &ossec_conf).await?;

    info!("Agent name updated to {}", agent_name);

    Ok(())
}
