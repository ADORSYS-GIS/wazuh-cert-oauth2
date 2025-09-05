use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::sync::{mpsc, oneshot, RwLock};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub subject: String,
    pub serial_hex: String,
    pub issued_at_unix: u64,
    pub revoked: bool,
    pub revoked_at_unix: Option<u64>,
    pub reason: Option<String>,
}

#[derive(Clone)]
pub struct Ledger {
    inner: Arc<RwLock<Vec<LedgerEntry>>>,
    tx: mpsc::Sender<Command>,
}

enum Command {
    RecordIssued {
        subject: String,
        serial_hex: String,
        issued_at_unix: u64,
        respond_to: oneshot::Sender<Result<()>>,
    },
    MarkRevoked {
        serial_hex: String,
        reason: Option<String>,
        revoked_at_unix: u64,
        respond_to: oneshot::Sender<Result<()>>,
    },
}

impl Ledger {
    pub async fn new(path: PathBuf) -> Result<Self> {
        let entries = if fs::try_exists(&path).await? {
            let data = fs::read(&path).await?;
            if data.is_empty() {
                Vec::new()
            } else {
                parse_csv(&String::from_utf8_lossy(&data))?
            }
        } else {
            Vec::new()
        };

        let inner = Arc::new(RwLock::new(entries));
        let (tx, mut rx) = mpsc::channel::<Command>(100);
        let path_clone = path.clone();
        let inner_clone = inner.clone();
        tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    Command::RecordIssued { subject, serial_hex, issued_at_unix, respond_to } => {
                        let res = async {
                            {
                                let mut guard = inner_clone.write().await;
                                guard.push(LedgerEntry {
                                    subject,
                                    serial_hex,
                                    issued_at_unix,
                                    revoked: false,
                                    revoked_at_unix: None,
                                    reason: None,
                                });
                            }
                            persist_csv(&path_clone, &inner_clone).await
                        }.await;
                        let _ = respond_to.send(res);
                    }
                    Command::MarkRevoked { serial_hex, reason, revoked_at_unix, respond_to } => {
                        let res = async {
                            {
                                let mut guard = inner_clone.write().await;
                                if let Some(entry) = guard
                                    .iter_mut()
                                    .rev()
                                    .find(|e| e.serial_hex.eq_ignore_ascii_case(&serial_hex))
                                {
                                    entry.revoked = true;
                                    entry.revoked_at_unix = Some(revoked_at_unix);
                                    entry.reason = reason.clone();
                                } else {
                                    // If no issuance record exists, create a minimal revoked record
                                    guard.push(LedgerEntry {
                                        subject: String::new(),
                                        serial_hex,
                                        issued_at_unix: 0,
                                        revoked: true,
                                        revoked_at_unix: Some(revoked_at_unix),
                                        reason: reason.clone(),
                                    });
                                }
                            }
                            persist_csv(&path_clone, &inner_clone).await
                        }.await;
                        let _ = respond_to.send(res);
                    }
                }
            }
        });

        Ok(Self { inner, tx })
    }

    pub async fn record_issued(&self, subject: String, serial_hex: String) -> Result<()> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Command::RecordIssued { subject, serial_hex, issued_at_unix: now, respond_to: tx })
            .await
            .map_err(|e| anyhow::anyhow!("ledger writer dropped: {}", e))?;
        rx.await.map_err(|e| anyhow::anyhow!("ledger writer closed: {}", e))??;
        Ok(())
    }

    pub async fn mark_revoked(&self, serial_hex: String, reason: Option<String>) -> Result<()> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Command::MarkRevoked { serial_hex, reason, revoked_at_unix: now, respond_to: tx })
            .await
            .map_err(|e| anyhow::anyhow!("ledger writer dropped: {}", e))?;
        rx.await.map_err(|e| anyhow::anyhow!("ledger writer closed: {}", e))??;
        Ok(())
    }

    pub async fn find_by_subject(&self, subject: &str) -> Vec<LedgerEntry> {
        self.inner
            .read()
            .await
            .iter()
            .filter(|e| e.subject == subject)
            .cloned()
            .collect()
    }

    pub async fn revoked_as_revocations(&self) -> Vec<crate::shared::crl::RevocationEntry> {
        self.inner
            .read()
            .await
            .iter()
            .filter(|e| e.revoked)
            .map(|e| crate::shared::crl::RevocationEntry {
                serial_hex: e.serial_hex.clone(),
                reason: e.reason.clone(),
                revoked_at_unix: e.revoked_at_unix.unwrap_or_default(),
            })
            .collect()
    }
}

async fn persist_csv(path: &PathBuf, inner: &Arc<RwLock<Vec<LedgerEntry>>>) -> Result<()> {
    let data = inner.read().await.clone();
    let mut out = String::new();
    out.push_str("subject,serial_hex,issued_at_unix,revoked,revoked_at_unix,reason\n");
    for e in data.iter() {
        let subject = escape_csv_field(&e.subject);
        let serial = escape_csv_field(&e.serial_hex);
        let issued = e.issued_at_unix.to_string();
        let revoked = if e.revoked { "true" } else { "false" };
        let revoked_at = e
            .revoked_at_unix
            .map(|v| v.to_string())
            .unwrap_or_default();
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

fn parse_csv(s: &str) -> Result<Vec<LedgerEntry>> {
    let mut out = Vec::new();
    for (idx, line) in s.lines().enumerate() {
        if idx == 0 {
            // header
            continue;
        }
        let line = line.trim_end();
        if line.is_empty() { continue; }
        let fields = split_csv_line(line);
        if fields.len() < 6 { continue; }
        let subject = unescape_csv_field(&fields[0]);
        let serial_hex = unescape_csv_field(&fields[1]);
        let issued_at_unix = fields[2].parse::<u64>().unwrap_or_default();
        let revoked = matches!(fields[3].as_str(), "true" | "TRUE" | "1");
        let revoked_at_unix = if fields[4].is_empty() { None } else { Some(fields[4].parse::<u64>().unwrap_or_default()) };
        let reason = {
            let r = unescape_csv_field(&fields[5]);
            if r.is_empty() { None } else { Some(r) }
        };
        out.push(LedgerEntry { subject, serial_hex, issued_at_unix, revoked, revoked_at_unix, reason });
    }
    Ok(out)
}

fn split_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                if in_quotes {
                    // lookahead for escaped quote
                    if let Some('"') = chars.peek() {
                        // escaped quote
                        cur.push('"');
                        let _ = chars.next();
                    } else {
                        in_quotes = false;
                    }
                } else {
                    in_quotes = true;
                }
            }
            ',' if !in_quotes => {
                fields.push(cur);
                cur = String::new();
            }
            _ => cur.push(c),
        }
    }
    fields.push(cur);
    fields
}

fn escape_csv_field(s: &str) -> String {
    let needs_quotes = s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r');
    if needs_quotes {
        let mut out = String::with_capacity(s.len() + 2);
        out.push('"');
        for ch in s.chars() {
            if ch == '"' { out.push('"'); out.push('"'); } else { out.push(ch); }
        }
        out.push('"');
        out
    } else {
        s.to_string()
    }
}

fn unescape_csv_field(s: &str) -> String {
    let s = s.trim();
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        let inner = &s[1..s.len()-1];
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '"' {
                if let Some('"') = chars.peek() { let _ = chars.next(); out.push('"'); }
            } else { out.push(c); }
        }
        out
    } else {
        s.to_string()
    }
}
