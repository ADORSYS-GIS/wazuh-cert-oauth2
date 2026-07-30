use std::time::{SystemTime, UNIX_EPOCH};

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
        fmt_timestamp(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        )
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
