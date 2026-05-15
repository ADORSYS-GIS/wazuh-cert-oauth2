/// Generate the Wazuh agent name from the subject claim.
pub fn generate_agent_name(claim_name: &str) -> String {
    let name = diacritics::remove_diacritics(claim_name);
    let long_machine_id = if let Ok(machine_id) = mid::get(&name) {
        machine_id
    } else {
        let r = rand::random::<u64>();
        format!("{:12}", r)
    };

    let small_machine_id = if long_machine_id.len() > 6 {
        long_machine_id[..6].to_string()
    } else if long_machine_id.len() < 6 {
        format!("{:0<6}", long_machine_id)
    } else {
        long_machine_id
    };

    format!("{}-{}", &name, small_machine_id).replace(|c: char| !c.is_ascii_alphanumeric(), "-")
}

#[cfg(test)]
mod tests {
    use super::generate_agent_name;

    #[test]
    fn name_is_ascii_alphanumeric_with_dashes() {
        let agent_name = generate_agent_name("DevOps SRE");
        assert!(
            agent_name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-'),
            "unexpected character in agent name: {}",
            agent_name
        );
    }

    #[test]
    fn name_contains_base_prefix() {
        // The generated name should start with the sanitized display name part.
        let agent_name = generate_agent_name("Alice Bob");
        assert!(
            agent_name.starts_with("Alice-Bob-"),
            "unexpected prefix in agent name: {}",
            agent_name
        );
    }
}
