use super::LedgerEntry;
use super::csv_utils::{escape_csv_field, split_csv_line, unescape_csv_field};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tokio::sync::RwLock;
use wazuh_cert_oauth2_model::models::errors::AppResult;

pub async fn persist_csv(path: &PathBuf, inner: &Arc<RwLock<Vec<LedgerEntry>>>) -> AppResult<()> {
    let data = inner.read().await.clone();
    let mut out = String::new();
    out.push_str("subject,serial_hex,issued_at_unix,revoked,revoked_at_unix,reason,issuer,realm\n");
    for e in data.iter() {
        let subject = escape_csv_field(&e.subject);
        let serial = escape_csv_field(&e.serial_hex);
        let issued = e.issued_at_unix.to_string();
        let revoked = if e.revoked { "true" } else { "false" };
        let revoked_at = e.revoked_at_unix.map(|v| v.to_string()).unwrap_or_default();
        let reason = e.reason.as_deref().unwrap_or("");
        let reason = escape_csv_field(reason);
        let issuer = e.issuer.as_deref().unwrap_or("");
        let issuer = escape_csv_field(issuer);
        let realm = e.realm.as_deref().unwrap_or("");
        let realm = escape_csv_field(realm);
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            subject, serial, issued, revoked, revoked_at, reason, issuer, realm
        ));
    }

    let tmp = path.with_extension("csv.tmp");
    fs::write(&tmp, out.as_bytes()).await?;
    fs::rename(tmp, path).await?;
    Ok(())
}

pub fn parse_csv(s: &str) -> AppResult<Vec<LedgerEntry>> {
    let mut out = Vec::new();
    for (idx, line) in s.lines().enumerate() {
        if idx == 0 {
            continue;
        }
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        let fields = split_csv_line(line);
        if fields.len() < 6 {
            continue;
        }
        let subject = unescape_csv_field(&fields[0]);
        let serial_hex = unescape_csv_field(&fields[1]);
        let issued_at_unix = fields[2].parse::<u64>().unwrap_or_default();
        let revoked = matches!(fields[3].as_str(), "true" | "TRUE" | "1");
        let revoked_at_unix = if fields[4].is_empty() {
            None
        } else {
            Some(fields[4].parse::<u64>().unwrap_or_default())
        };
        let reason = {
            let r = unescape_csv_field(&fields[5]);
            if r.is_empty() { None } else { Some(r) }
        };
        // Optional fields for backward compatibility
        let issuer = if fields.len() > 6 {
            let v = unescape_csv_field(&fields[6]);
            if v.is_empty() { None } else { Some(v) }
        } else {
            None
        };
        let realm = if fields.len() > 7 {
            let v = unescape_csv_field(&fields[7]);
            if v.is_empty() { None } else { Some(v) }
        } else {
            None
        };
        out.push(LedgerEntry {
            subject,
            serial_hex,
            issued_at_unix,
            revoked,
            revoked_at_unix,
            reason,
            issuer,
            realm,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{parse_csv, persist_csv};
    use crate::shared::ledger::LedgerEntry;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::fs;
    use tokio::sync::RwLock;

    fn unique_csv_path() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos();
        std::env::temp_dir()
            .join(format!("wazuh-ledger-csv-{}", nanos))
            .join("ledger.csv")
    }

    #[test]
    fn parse_csv_supports_legacy_rows_without_issuer_or_realm() {
        let csv = concat!(
            "subject,serial_hex,issued_at_unix,revoked,revoked_at_unix,reason,issuer,realm\n",
            "user-a,ABC123,100,true,200,manual revoke\n"
        );
        let rows = parse_csv(csv).expect("csv should parse");
        assert_eq!(rows.len(), 1);

        let row = &rows[0];
        assert_eq!(row.subject, "user-a");
        assert_eq!(row.serial_hex, "ABC123");
        assert_eq!(row.issued_at_unix, 100);
        assert!(row.revoked);
        assert_eq!(row.revoked_at_unix, Some(200));
        assert_eq!(row.reason.as_deref(), Some("manual revoke"));
        assert_eq!(row.issuer, None);
        assert_eq!(row.realm, None);
    }

    #[test]
    fn parse_csv_unescapes_quoted_fields() {
        let csv = concat!(
            "subject,serial_hex,issued_at_unix,revoked,revoked_at_unix,reason,issuer,realm\n",
            "\"user,1\",ABC123,100,1,200,\"reason \"\"with quotes\"\"\",https://issuer/realms/dev,dev\n"
        );
        let rows = parse_csv(csv).expect("csv should parse");
        assert_eq!(rows.len(), 1);

        let row = &rows[0];
        assert_eq!(row.subject, "user,1");
        assert_eq!(row.reason.as_deref(), Some("reason \"with quotes\""));
        assert_eq!(row.issuer.as_deref(), Some("https://issuer/realms/dev"));
        assert_eq!(row.realm.as_deref(), Some("dev"));
    }

    #[tokio::test]
    async fn persist_csv_round_trips_entries() {
        let path = unique_csv_path();
        let parent = path.parent().expect("path should have parent");
        fs::create_dir_all(parent)
            .await
            .expect("temp dir should be created");

        let entries = vec![
            LedgerEntry {
                subject: "user-a".to_string(),
                serial_hex: "AA11".to_string(),
                issued_at_unix: 111,
                revoked: false,
                revoked_at_unix: None,
                reason: None,
                issuer: Some("https://issuer/realms/main".to_string()),
                realm: Some("main".to_string()),
            },
            LedgerEntry {
                subject: "user-b".to_string(),
                serial_hex: "BB22".to_string(),
                issued_at_unix: 222,
                revoked: true,
                revoked_at_unix: Some(333),
                reason: Some("operator request".to_string()),
                issuer: None,
                realm: None,
            },
        ];

        let shared = Arc::new(RwLock::new(entries.clone()));
        persist_csv(&path, &shared).await.expect("persist should work");

        let written = fs::read_to_string(&path).await.expect("csv should exist");
        let parsed = parse_csv(&written).expect("persisted csv should parse");
        assert_eq!(parsed.len(), entries.len());
        assert_eq!(parsed[0].subject, entries[0].subject);
        assert_eq!(parsed[0].issuer, entries[0].issuer);
        assert_eq!(parsed[1].revoked, entries[1].revoked);
        assert_eq!(parsed[1].reason, entries[1].reason);

        let _ = fs::remove_dir_all(parent).await;
    }
}
