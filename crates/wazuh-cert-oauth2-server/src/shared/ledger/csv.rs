use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tokio::sync::RwLock;

use super::LedgerEntry;
use super::csv_utils::{escape_csv_field, split_csv_line, unescape_csv_field};

#[inline]
pub async fn persist_csv(path: &PathBuf, inner: &Arc<RwLock<Vec<LedgerEntry>>>) -> Result<()> {
    let data = inner.read().await.clone();
    let mut out = String::new();
    out.push_str("subject,serial_hex,issued_at_unix,revoked,revoked_at_unix,reason\n");
    for e in data.iter() {
        let subject = escape_csv_field(&e.subject);
        let serial = escape_csv_field(&e.serial_hex);
        let issued = e.issued_at_unix.to_string();
        let revoked = if e.revoked { "true" } else { "false" };
        let revoked_at = e.revoked_at_unix.map(|v| v.to_string()).unwrap_or_default();
        let reason = e.reason.as_deref().unwrap_or("");
        let reason = escape_csv_field(reason);
        out.push_str(&format!(
            "{},{},{},{},{},{}\n",
            subject, serial, issued, revoked, revoked_at, reason
        ));
    }

    let tmp = path.with_extension("csv.tmp");
    fs::write(&tmp, out.as_bytes()).await?;
    fs::rename(tmp, path).await?;
    Ok(())
}

#[inline]
pub fn parse_csv(s: &str) -> Result<Vec<LedgerEntry>> {
    let mut out = Vec::new();
    for (idx, line) in s.lines().enumerate() {
        if idx == 0 { continue; }
        let line = line.trim_end();
        if line.is_empty() { continue; }
        let fields = split_csv_line(line);
        if fields.len() < 6 { continue; }
        let subject = unescape_csv_field(&fields[0]);
        let serial_hex = unescape_csv_field(&fields[1]);
        let issued_at_unix = fields[2].parse::<u64>().unwrap_or_default();
        let revoked = matches!(fields[3].as_str(), "true" | "TRUE" | "1");
        let revoked_at_unix = if fields[4].is_empty() { None } else { Some(fields[4].parse::<u64>().unwrap_or_default()) };
        let reason = { let r = unescape_csv_field(&fields[5]); if r.is_empty() { None } else { Some(r) } };
        out.push(LedgerEntry { subject, serial_hex, issued_at_unix, revoked, revoked_at_unix, reason });
    }
    Ok(out)
}
