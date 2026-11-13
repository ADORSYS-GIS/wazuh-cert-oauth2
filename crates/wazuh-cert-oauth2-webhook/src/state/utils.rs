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

/// Build a unique temporary directory for tests.
///
/// The clock alone is not unique enough: tests run in parallel and can observe
/// the same timestamp, which makes them share (and delete) each other's dirs.
#[cfg(test)]
pub(crate) fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic")
        .as_nanos();
    let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}-{unique}", std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::{ensure_spool_dir, unique_temp_dir};
    use std::path::PathBuf;

    fn unique_dir() -> PathBuf {
        unique_temp_dir("wazuh-webhook-utils-test")
    }

    #[test]
    fn ensure_spool_dir_creates_missing_directory() {
        let dir = unique_dir();
        ensure_spool_dir(&dir);
        assert!(dir.exists());
        let _ = std::fs::remove_dir_all(dir);
    }
}
