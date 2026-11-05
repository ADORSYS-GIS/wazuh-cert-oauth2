use std::path::Path;

use wazuh_cert_oauth2_model::models::errors::AppResult;

use crate::shared::ledger::csv_utils::escape_csv_field;

/// An entry from the ledger that could not be matched to any Wazuh agent.
///
/// The `reason` field may contain additional context such as agent IDs
/// when the cause is an ambiguous match (multiple agents sharing the
/// same name prefix).
pub struct UnresolvedEntry {
    pub subject: String,
    pub serial_hex: String,
    pub issued_at_unix: u64,
    pub reason: String,
}

/// Write the unresolved CSV artifact.
///
/// The field-escaping logic here (`escape_csv_field`) is intentionally shared
/// with the main ledger CSV writer at `crate::shared::ledger::csv::persist_csv`
/// so that escaping edge cases (commas, quotes, newlines) are handled consistently.
/// If a new column is added to the main ledger format, consider whether this
/// writer also needs to be updated.
pub fn write_unresolved_csv(path: &Path, entries: &[UnresolvedEntry]) -> AppResult<()> {
    let mut out = String::from(
        "# Unresolved ledger entries (could not match to a Wazuh agent)\n\
         subject,serial_hex,issued_at_unix,reason\n",
    );
    for r in entries {
        out.push_str(&format!(
            "{},{},{},{}\n",
            escape_csv_field(&r.subject),
            escape_csv_field(&r.serial_hex),
            r.issued_at_unix,
            escape_csv_field(&r.reason),
        ));
    }
    std::fs::write(path, out.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{UnresolvedEntry, write_unresolved_csv};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn temp_path() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!("unresolved-test-{}-{}.csv", std::process::id(), n))
    }

    #[test]
    fn writes_header_and_rows() {
        let path = temp_path();
        let entries = vec![
            UnresolvedEntry {
                subject: "user-1".into(),
                serial_hex: "ABCD".into(),
                issued_at_unix: 1700000000,
                reason: "unmatched_no_match".into(),
            },
            UnresolvedEntry {
                subject: "user-2".into(),
                serial_hex: "1234".into(),
                issued_at_unix: 1700000001,
                reason: "ambiguous_multiple_agents".into(),
            },
        ];

        write_unresolved_csv(&path, &entries).expect("write should succeed");
        let content = std::fs::read_to_string(&path).expect("file should be readable");
        std::fs::remove_file(&path).ok();

        assert!(content.starts_with("# Unresolved ledger entries"));
        assert!(content.contains("subject,serial_hex,issued_at_unix,reason"));
        assert!(content.contains("user-1,ABCD,1700000000,unmatched_no_match"));
        assert!(content.contains("user-2,1234,1700000001,ambiguous_multiple_agents"));
    }

    #[test]
    fn escapes_commas_quotes_and_newlines_in_fields() {
        let path = temp_path();
        let entries = vec![UnresolvedEntry {
            subject: "user,with\"comma".into(),
            serial_hex: "00FF".into(),
            issued_at_unix: 1,
            reason: "line\nbreak".into(),
        }];

        write_unresolved_csv(&path, &entries).expect("write should succeed");
        let content = std::fs::read_to_string(&path).expect("file should be readable");
        std::fs::remove_file(&path).ok();

        // The escaped subject must not break the CSV column structure: commas
        // and quotes are wrapped in quotes with doubled inner quotes.
        assert!(content.contains("\"user,with\"\"comma\""));
        assert!(content.contains("00FF"));
    }

    #[test]
    fn writes_only_header_when_no_entries() {
        let path = temp_path();
        write_unresolved_csv(&path, &[]).expect("write should succeed");
        let content = std::fs::read_to_string(&path).expect("file should be readable");
        std::fs::remove_file(&path).ok();

        assert!(content.contains("subject,serial_hex,issued_at_unix,reason"));
        // No data rows beyond the header.
        assert_eq!(content.lines().count(), 2);
    }
}
