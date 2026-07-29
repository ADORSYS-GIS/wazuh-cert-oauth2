use wazuh_cert_oauth2_model::services::wazuh::AgentItem;

#[derive(Clone, Debug)]
pub struct MatchResult {
    pub agent_name: String,
}

/// Sanitize a name for agent name prefix matching.
///
/// This mirrors the sanitization in `generate_agent_name` (client-side):
/// removes diacritics, replaces non-alphanumeric chars with `-`.
pub fn sanitize_name(name: &str) -> String {
    let name = diacritics::remove_diacritics(name);
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

/// Try to match a Keycloak user display name to a Wazuh agent.
///
/// Returns:
/// - `Ok(Some(MatchResult))` — exactly one agent matched.
/// - `Ok(None)` — no agent matched.
/// - `Err(candidates)` — multiple agents matched the prefix. The vector
///   contains `(agent_id, agent_name)` pairs for human disambiguation.
///   A match is rejected rather than silently picking one because
///   agent names include a machine-ID suffix, so multiple agents with
///   the same prefix mean the same user enrolled from multiple devices.
pub fn find_match(
    kc_name: &str,
    agents: &[AgentItem],
) -> Result<Option<MatchResult>, Vec<(String, String)>> {
    let prefix = sanitize_name(kc_name);
    let prefix_lower = prefix.to_ascii_lowercase();

    let mut matched: Vec<&AgentItem> = agents
        .iter()
        .filter(|a| a.name.starts_with(&format!("{}-", prefix)))
        .collect();

    if matched.is_empty() {
        matched = agents
            .iter()
            .filter(|a| {
                a.name
                    .to_ascii_lowercase()
                    .starts_with(&format!("{}-", prefix_lower))
            })
            .collect();
    }

    if matched.len() == 1 {
        return Ok(Some(MatchResult {
            agent_name: matched[0].name.clone(),
        }));
    }

    if matched.is_empty() {
        return Ok(None);
    }

    // Multiple agents share the same prefix — the enrolled-from-multiple-devices case.
    // Don't silently pick one; return candidates for human review.
    Err(matched
        .iter()
        .map(|a| (a.id.clone(), a.name.clone()))
        .collect())
}
