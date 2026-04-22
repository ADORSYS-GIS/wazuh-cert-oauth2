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

#[cfg(test)]
mod tests {
    use super::ensure_spool_dir;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos();
        std::env::temp_dir().join(format!("wazuh-webhook-utils-test-{}", nanos))
    }

    #[test]
    fn ensure_spool_dir_creates_missing_directory() {
        let dir = unique_dir();
        ensure_spool_dir(&dir);
        assert!(dir.exists());
        let _ = std::fs::remove_dir_all(dir);
    }
}
