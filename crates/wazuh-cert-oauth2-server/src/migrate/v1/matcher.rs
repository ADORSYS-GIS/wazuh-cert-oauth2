use tracing::debug;
use wazuh_cert_oauth2_model::services::wazuh::AgentItem;

#[derive(Clone, Debug)]
pub struct MatchResult {
    pub agent_name: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum MatchStatus {
    Matched,
    SkippedRevoked,
    SkippedAlreadyPresent,
    UnmatchedNoKeycloak,
    UnmatchedNoMatch,
    AmbiguousMultipleAgents(Vec<(String, String)>),
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

    let search_prefix = format!("{}-", prefix);
    let search_prefix_lower = format!("{}-", prefix_lower);

    debug!(
        prefix = %search_prefix,
        agent_count = agents.len(),
        agent_names = ?agents.iter().map(|a| &a.name).collect::<Vec<_>>(),
        "Attempting to match Keycloak name to Wazuh agent"
    );

    let mut matched: Vec<&AgentItem> = agents
        .iter()
        .filter(|a| a.name.starts_with(&search_prefix))
        .collect();

    if matched.is_empty() {
        matched = agents
            .iter()
            .filter(|a| {
                a.name
                    .to_ascii_lowercase()
                    .starts_with(&search_prefix_lower)
            })
            .collect();
    }

    debug!(
        matched = matched.len(),
        matched_names = ?matched.iter().map(|a| &a.name).collect::<Vec<_>>(),
        "Match result"
    );

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

#[cfg(test)]
mod tests {
    use super::{MatchStatus, find_match, sanitize_name};
    use wazuh_cert_oauth2_model::services::wazuh::AgentItem;

    fn agent(id: &str, name: &str) -> AgentItem {
        AgentItem {
            id: id.to_string(),
            name: name.to_string(),
            os: None,
        }
    }

    #[test]
    fn sanitize_removes_diacritics_and_replaces_special_chars() {
        assert_eq!(sanitize_name("José"), "Jose");
        assert_eq!(sanitize_name("Jean-Luc"), "Jean-Luc");
        assert_eq!(sanitize_name("A B C"), "A-B-C");
        assert_eq!(sanitize_name("naïve"), "naive");
        assert_eq!(sanitize_name(""), "");
    }

    #[test]
    fn matches_exact_prefix() {
        let agents = vec![agent("001", "alice-abc123"), agent("002", "bob-def456")];
        let result = find_match("Alice", &agents).expect("should not be ambiguous");
        assert_eq!(result.unwrap().agent_name, "alice-abc123");
    }

    #[test]
    fn falls_back_to_case_insensitive_match() {
        let agents = vec![agent("001", "ALICE-abc123")];
        let result = find_match("alice", &agents).expect("should not be ambiguous");
        assert_eq!(result.unwrap().agent_name, "ALICE-abc123");
    }

    #[test]
    fn returns_none_when_no_agent_matches() {
        let agents = vec![agent("001", "carol-xyz")];
        assert!(
            find_match("Alice", &agents)
                .expect("should not be ambiguous")
                .is_none()
        );
    }

    #[test]
    fn returns_ambiguous_candidates_when_multiple_match() {
        let agents = vec![agent("001", "alice-aaa"), agent("002", "alice-bbb")];
        let err = find_match("Alice", &agents).expect_err("multiple matches should be ambiguous");
        assert_eq!(err.len(), 2);
        assert!(err.contains(&("001".to_string(), "alice-aaa".to_string())));
        assert!(err.contains(&("002".to_string(), "alice-bbb".to_string())));
    }

    #[test]
    fn match_status_variants_are_distinct() {
        // Sanity check that the enum is usable in comparisons (PartialEq).
        assert_ne!(MatchStatus::Matched, MatchStatus::UnmatchedNoMatch);
        assert_eq!(
            MatchStatus::AmbiguousMultipleAgents(vec![("1".into(), "a".into())]),
            MatchStatus::AmbiguousMultipleAgents(vec![("1".into(), "a".into())])
        );
    }
}
