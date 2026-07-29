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
