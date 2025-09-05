use anyhow::Result;
use std::path::PathBuf;
use tokio::fs;

use super::csv::parse_csv;
use super::LedgerEntry;

#[inline]
pub async fn load_entries(path: &PathBuf) -> Result<Vec<LedgerEntry>> {
    if !fs::try_exists(path).await? {
        return Ok(Vec::new());
    }
    let data = fs::read(path).await?;
    if data.is_empty() {
        return Ok(Vec::new());
    }
    parse_csv(&String::from_utf8_lossy(&data))
}

