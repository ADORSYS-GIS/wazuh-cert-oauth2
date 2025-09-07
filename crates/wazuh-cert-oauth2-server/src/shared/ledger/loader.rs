use super::LedgerEntry;
use super::csv::parse_csv;
use std::path::PathBuf;
use tokio::fs;
use wazuh_cert_oauth2_model::models::errors::AppResult;

pub async fn load_entries(path: &PathBuf) -> AppResult<Vec<LedgerEntry>> {
    if !fs::try_exists(path).await? {
        return Ok(Vec::new());
    }

    let data = fs::read(path).await?;
    if data.is_empty() {
        return Ok(Vec::new());
    }
    parse_csv(&String::from_utf8_lossy(&data))
}
