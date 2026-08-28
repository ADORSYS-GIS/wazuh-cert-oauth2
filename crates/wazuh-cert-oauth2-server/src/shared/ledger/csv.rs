use super::LedgerEntry;
use super::csv_utils::{escape_csv_field, split_csv_line, unescape_csv_field};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tokio::sync::RwLock;
use wazuh_cert_oauth2_model::models::errors::AppResult;
use wazuh_cert_oauth2_model::models::ledger_entry::CERTIFICATE_VALIDITY_DAYS;

pub async fn persist_csv(path: &PathBuf, inner: &Arc<RwLock<Vec<LedgerEntry>>>) -> AppResult<()> {
    let data = inner.read().await.clone();
    let mut out = String::new();
    out.push_str("subject,serial_hex,issued_at_unix,not_after_unix,revoked,revoked_at_unix,reason,issuer,realm,wazuh_agent_name\n");
    for e in data.iter() {
        let subject = escape_csv_field(&e.subject);
        let serial = escape_csv_field(&e.serial_hex);
        let issued = e.issued_at_unix.to_string();
        let not_after = e.not_after_unix.to_string();
        let revoked = if e.revoked { "true" } else { "false" };
        let revoked_at = e.revoked_at_unix.map(|v| v.to_string()).unwrap_or_default();
        let reason = e.reason.as_deref().unwrap_or("");
        let reason = escape_csv_field(reason);
        let issuer = e.issuer.as_deref().unwrap_or("");
        let issuer = escape_csv_field(issuer);
        let realm = e.realm.as_deref().unwrap_or("");
        let realm = escape_csv_field(realm);
        let agent_name = e.wazuh_agent_name.as_deref().unwrap_or("");
        let agent_name = escape_csv_field(agent_name);
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{}\n",
            subject,
            serial,
            issued,
            not_after,
            revoked,
            revoked_at,
            reason,
            issuer,
            realm,
            agent_name
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
        let default_not_after_unix =
            issued_at_unix.saturating_add(CERTIFICATE_VALIDITY_DAYS.saturating_mul(86_400));

        // Detect new format (≥9 fields) which includes not_after_unix at index 3.
        let (
            not_after_unix,
            revoked_idx,
            revoked_at_idx,
            reason_idx,
            issuer_idx,
            realm_idx,
            agent_idx,
        ) = if fields.len() >= 9 {
            let raw = fields[3].trim();
            (
                if raw.is_empty() || raw == "0" {
                    default_not_after_unix
                } else {
                    raw.parse::<u64>().unwrap_or(default_not_after_unix)
                },
                4,
                5,
                6,
                7,
                8,
                9,
            )
        } else {
            // Legacy format: no not_after_unix column. Reconstruct it from the
            // issuing timestamp so old CSV entries remain valid until their
            // certificate expiry window elapses.
            (default_not_after_unix, 3, 4, 5, 6, 7, 8)
        };
        let revoked = matches!(fields[revoked_idx].as_str(), "true" | "TRUE" | "1");
        let revoked_at_unix = if fields[revoked_at_idx].is_empty() {
            None
        } else {
            Some(fields[revoked_at_idx].parse::<u64>().unwrap_or_default())
        };
        let reason = {
            let r = unescape_csv_field(&fields[reason_idx]);
            if r.is_empty() { None } else { Some(r) }
        };
        // Optional fields for backward compatibility
        let issuer = if fields.len() > issuer_idx {
            let v = unescape_csv_field(&fields[issuer_idx]);
            if v.is_empty() { None } else { Some(v) }
        } else {
            None
        };
        let realm = if fields.len() > realm_idx {
            let v = unescape_csv_field(&fields[realm_idx]);
            if v.is_empty() { None } else { Some(v) }
        } else {
            None
        };
        let wazuh_agent_name = if fields.len() > agent_idx {
            let v = unescape_csv_field(&fields[agent_idx]);
            if v.is_empty() { None } else { Some(v) }
        } else {
            None
        };
        out.push(LedgerEntry {
            subject,
            serial_hex,
            issued_at_unix,
            not_after_unix,
            revoked,
            revoked_at_unix,
            reason,
            issuer,
            realm,
            wazuh_agent_name,
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
    use wazuh_cert_oauth2_model::models::ledger_entry::CERTIFICATE_VALIDITY_DAYS;

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
            "subject,serial_hex,issued_at_unix,revoked,revoked_at_unix,reason,issuer,realm,wazuh_agent_name\n",
            "user-a,ABC123,100,true,200,manual revoke\n"
        );
        let rows = parse_csv(csv).expect("csv should parse");
        assert_eq!(rows.len(), 1);

        let row = &rows[0];
        assert_eq!(row.subject, "user-a");
        assert_eq!(row.serial_hex, "ABC123");
        assert_eq!(row.issued_at_unix, 100);
        assert_eq!(row.not_after_unix, 100 + CERTIFICATE_VALIDITY_DAYS * 86_400);
        assert!(row.revoked);
        assert_eq!(row.revoked_at_unix, Some(200));
        assert_eq!(row.reason.as_deref(), Some("manual revoke"));
        assert_eq!(row.issuer, None);
        assert_eq!(row.realm, None);
        assert_eq!(row.wazuh_agent_name, None);
    }

    #[test]
    fn parse_csv_unescapes_quoted_fields() {
        let csv = concat!(
            "subject,serial_hex,issued_at_unix,not_after_unix,revoked,revoked_at_unix,reason,issuer,realm,wazuh_agent_name\n",
            "\"user,1\",ABC123,100,9999999999,1,200,\"reason \"\"with quotes\"\"\",https://issuer/realms/dev,dev,DevOps-SRE-123\n"
        );
        let rows = parse_csv(csv).expect("csv should parse");
        assert_eq!(rows.len(), 1);

        let row = &rows[0];
        assert_eq!(row.subject, "user,1");
        assert_eq!(row.not_after_unix, 9999999999);
        assert_eq!(row.reason.as_deref(), Some("reason \"with quotes\""));
        assert_eq!(row.issuer.as_deref(), Some("https://issuer/realms/dev"));
        assert_eq!(row.realm.as_deref(), Some("dev"));
        assert_eq!(row.wazuh_agent_name.as_deref(), Some("DevOps-SRE-123"));
    }

    #[test]
    fn parse_csv_computes_not_after_for_legacy_rows() {
        let csv = concat!(
            "subject,serial_hex,issued_at_unix,revoked,revoked_at_unix,reason,issuer,realm,wazuh_agent_name\n",
            "user-a,ABC123,100,true,200,manual revoke,https://issuer/realms/dev,dev,DevOps-SRE-123\n"
        );
        let rows = parse_csv(csv).expect("csv should parse");
        assert_eq!(rows.len(), 1);

        let row = &rows[0];
        assert_eq!(row.not_after_unix, 100 + CERTIFICATE_VALIDITY_DAYS * 86_400);
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
                not_after_unix: 31_622_400,
                revoked: false,
                revoked_at_unix: None,
                reason: None,
                issuer: Some("https://issuer/realms/main".to_string()),
                realm: Some("main".to_string()),
                wazuh_agent_name: Some("DevOps-SRE-main".to_string()),
            },
            LedgerEntry {
                subject: "user-b".to_string(),
                serial_hex: "BB22".to_string(),
                issued_at_unix: 222,
                not_after_unix: 31_622_500,
                revoked: true,
                revoked_at_unix: Some(333),
                reason: Some("operator request".to_string()),
                issuer: None,
                realm: None,
                wazuh_agent_name: None,
            },
        ];

        let shared = Arc::new(RwLock::new(entries.clone()));
        persist_csv(&path, &shared)
            .await
            .expect("persist should work");

        let written = fs::read_to_string(&path).await.expect("csv should exist");
        let parsed = parse_csv(&written).expect("persisted csv should parse");
        assert_eq!(parsed.len(), entries.len());
        assert_eq!(parsed[0].subject, entries[0].subject);
        assert_eq!(parsed[0].issuer, entries[0].issuer);
        assert_eq!(parsed[0].not_after_unix, 31_622_400);
        assert_eq!(parsed[1].revoked, entries[1].revoked);
        assert_eq!(parsed[1].reason, entries[1].reason);
        assert_eq!(parsed[1].not_after_unix, 31_622_500);

        let _ = fs::remove_dir_all(parent).await;
    }
}
