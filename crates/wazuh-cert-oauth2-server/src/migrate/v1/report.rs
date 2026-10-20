use wazuh_cert_oauth2_model::models::ledger_entry::LedgerEntry;

use crate::migrate::v1::matcher::{MatchResult, MatchStatus};
use crate::migrate::v1::opts::MigrateOpt;

pub fn generate(
    entries: &[LedgerEntry],
    results: &[Option<MatchResult>],
    statuses: &[MatchStatus],
    agent_count: usize,
    kc_available: bool,
    opt: &MigrateOpt,
) -> String {
    let total = entries.len();
    let matched_count = results.iter().filter(|r| r.is_some()).count();
    let active_count = statuses
        .iter()
        .filter(|s| **s != MatchStatus::SkippedRevoked)
        .count();
    let skipped_revoked = statuses
        .iter()
        .filter(|s| **s == MatchStatus::SkippedRevoked)
        .count();
    let skipped_already = statuses
        .iter()
        .filter(|s| **s == MatchStatus::SkippedAlreadyPresent)
        .count();

    let mut report = String::new();
    report.push_str("=== Migration Report ===\n");
    report.push_str(&format!(
        "Timestamp: {}\n",
        fmt_timestamp(wazuh_cert_oauth2_model::models::now_unix())
    ));
    report.push_str(&format!("Input: {}\n", opt.input));
    report.push_str(&format!("Output: {}\n", opt.output));
    report.push_str(&format!("Wazuh agents found: {}\n", agent_count));
    report.push_str(&format!("Keycloak available: {}\n", kc_available));
    report.push('\n');

    report.push_str(&format!(
        "{:<40} {:<35} {:<25} {}\n",
        "subject", "wazuh_agent_name", "status", "issued_at"
    ));
    report.push_str(&format!("{:=<40} {:=<35} {:=<25} {}\n", "", "", "", ""));

    for (i, e) in entries.iter().enumerate() {
        let name = results[i]
            .as_ref()
            .map(|m| m.agent_name.as_str())
            .unwrap_or("-");
        let status_label = match &statuses[i] {
            MatchStatus::Matched => "matched",
            MatchStatus::SkippedRevoked => "skipped_revoked",
            MatchStatus::SkippedAlreadyPresent => "skipped_already_present",
            MatchStatus::UnmatchedNoKeycloak => "unmatched",
            MatchStatus::UnmatchedNoMatch => "unmatched",
            MatchStatus::AmbiguousMultipleAgents(..) => "unmatched",
        };
        report.push_str(&format!(
            "{:<40} {:<35} {:<25} {}\n",
            e.subject, name, status_label, e.issued_at_unix
        ));
    }

    report.push('\n');
    report.push_str("=== Summary ===\n");
    report.push_str(&format!("Total ledger entries:     {}\n", total));
    report.push_str(&format!("  Active (non-revoked):   {}\n", active_count));
    report.push_str(&format!("  Revoked (skipped):      {}\n", skipped_revoked));
    report.push_str(&format!("  Already had name:       {}\n", skipped_already));
    report.push_str(&format!("Matched:                  {}\n", matched_count));
    report.push_str(&format!(
        "  (of {} active entries)  {:.1}%\n",
        active_count,
        if active_count > 0 {
            matched_count as f64 / active_count as f64 * 100.0
        } else {
            0.0
        }
    ));
    report.push_str(&format!(
        "Unmatched:                {}\n",
        active_count.saturating_sub(matched_count + skipped_already)
    ));
    report.push_str(&format!(
        "  (of {} active entries)  {:.1}%\n",
        active_count,
        if active_count > 0 {
            (active_count - matched_count - skipped_already) as f64 / active_count as f64 * 100.0
        } else {
            0.0
        }
    ));
    report.push('\n');

    let unmatched = active_count.saturating_sub(matched_count + skipped_already);
    if unmatched > 0 {
        report.push_str(&format!(
            "WARNING: {} active entries could not be matched.\n",
            unmatched,
        ));
        report.push_str(&format!(
            "  Review {} and update {} before restoring.\n",
            opt.unresolved, opt.output
        ));
        report.push_str(&format!(
            "  ({} revoked entries were left unchanged — their agents were already evicted.)\n",
            skipped_revoked,
        ));
    } else {
        report.push_str("SUCCESS: All active entries matched.\n");
        if skipped_revoked > 0 {
            report.push_str(&format!(
                "  ({} revoked entries were left unchanged.)\n",
                skipped_revoked,
            ));
        }
    }

    report
}

fn fmt_timestamp(unix_secs: u64) -> String {
    let secs = unix_secs as i64;

    chrono::DateTime::from_timestamp(secs, 0)
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::generate;
    use crate::migrate::v1::matcher::{MatchResult, MatchStatus};
    use crate::migrate::v1::opts::{KeycloakAuthMethod, MigrateOpt};
    use wazuh_cert_oauth2_model::models::ledger_entry::LedgerEntry;

    fn entry(subject: &str, revoked: bool) -> LedgerEntry {
        LedgerEntry {
            subject: subject.to_string(),
            serial_hex: "00FF".to_string(),
            issued_at_unix: 1700000000,
            not_after_unix: 1731536000,
            revoked,
            revoked_at_unix: if revoked { Some(1700000001) } else { None },
            reason: None,
            issuer: None,
            realm: None,
            wazuh_agent_name: None,
        }
    }

    fn opt() -> MigrateOpt {
        MigrateOpt {
            input: "/data/ledger.csv".to_string(),
            output: "ledger-migrated.csv".to_string(),
            unresolved: "unresolved.csv".to_string(),
            report: "migration-report.txt".to_string(),
            wazuh_manager_url: "https://wazuh".to_string(),
            wazuh_api_user: "user".to_string(),
            wazuh_api_password: "pass".to_string(),
            wazuh_tls_verify: true,
            wazuh_ca_bundle: None,
            keycloak_admin_url: "https://kc".to_string(),
            keycloak_realm: "main".to_string(),
            keycloak_auth_method: KeycloakAuthMethod::Password,
            keycloak_admin_user: Some("admin".to_string()),
            keycloak_admin_password: Some("secret".to_string()),
            keycloak_client_id: None,
            keycloak_client_secret: None,
            keycloak_tls_verify: true,
            keycloak_ca_bundle: None,
        }
    }

    #[test]
    fn reports_success_when_all_active_entries_match() {
        let entries = vec![entry("user-1", false), entry("user-2", false)];
        let results = vec![
            Some(MatchResult {
                agent_name: "user-1-abc".to_string(),
            }),
            Some(MatchResult {
                agent_name: "user-2-def".to_string(),
            }),
        ];
        let statuses = vec![MatchStatus::Matched, MatchStatus::Matched];

        let report = generate(&entries, &results, &statuses, 2, true, &opt());
        assert!(report.contains("=== Migration Report ==="));
        assert!(report.contains("Total ledger entries:     2"));
        assert!(report.contains("Matched:                  2"));
        assert!(report.contains("SUCCESS: All active entries matched."));
        assert!(report.contains("user-1"));
        assert!(report.contains("user-1-abc"));
    }

    #[test]
    fn reports_warning_when_entries_unmatched() {
        let entries = vec![entry("user-1", false)];
        let results = vec![None];
        let statuses = vec![MatchStatus::UnmatchedNoMatch];

        let report = generate(&entries, &results, &statuses, 1, true, &opt());
        assert!(report.contains("WARNING: 1 active entries could not be matched."));
        assert!(report.contains("Unmatched:                1"));
        assert!(report.contains("unresolved.csv"));
    }

    #[test]
    fn counts_revoked_and_already_present_entries() {
        let entries = vec![
            entry("user-1", true),
            entry("user-2", false),
            entry("user-3", false),
        ];
        let results = vec![
            None,
            None,
            Some(MatchResult {
                agent_name: "u3-x".into(),
            }),
        ];
        let statuses = vec![
            MatchStatus::SkippedRevoked,
            MatchStatus::SkippedAlreadyPresent,
            MatchStatus::Matched,
        ];

        let report = generate(&entries, &results, &statuses, 3, true, &opt());
        assert!(report.contains("Revoked (skipped):      1"));
        assert!(report.contains("Already had name:       1"));
        assert!(report.contains("Active (non-revoked):   2"));
    }

    #[test]
    fn handles_zero_active_entries_without_division_by_zero() {
        let entries = vec![entry("user-1", true)];
        let results = vec![None];
        let statuses = vec![MatchStatus::SkippedRevoked];

        let report = generate(&entries, &results, &statuses, 0, false, &opt());
        assert!(report.contains("Active (non-revoked):   0"));
        assert!(report.contains("0.0%"));
        assert!(report.contains("Keycloak available: false"));
    }
}
