use crate::shared::path::default_path_to_ossec_conf;
use crate::shared::replace_tag::replace_tag;
use wazuh_cert_oauth2_model::models::errors::AppResult;

/// Set the name of the agent.
pub async fn set_name(agent_name: &str) -> AppResult<()> {
    info!("Setting agent name to {}", agent_name);
    let ossec_conf = default_path_to_ossec_conf();

    replace_tag(&ossec_conf, "agent_name", agent_name).await?;

    info!("Agent name updated to {}", agent_name);

    Ok(())
}
