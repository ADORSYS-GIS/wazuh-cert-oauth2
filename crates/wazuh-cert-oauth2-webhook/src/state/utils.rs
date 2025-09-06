use std::fs;
use std::path::Path;

use tracing::warn;

pub(crate) fn ensure_spool_dir(spool_dir: &Path) {
    if !spool_dir.exists()
        && let Err(e) = fs::create_dir_all(spool_dir)
    {
        warn!("failed to create spool dir: {}", e);
    }
}
