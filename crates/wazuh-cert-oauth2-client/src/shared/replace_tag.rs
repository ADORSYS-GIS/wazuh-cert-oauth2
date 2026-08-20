use std::path::Path;
use tokio::fs;
use wazuh_cert_oauth2_model::models::errors::AppResult;

/// Replace the body of every `<tag>...</tag>` pair in a config file.
///
/// Done in-process (no `sed`/`gsed` subprocess) so enrollment doesn't depend on
/// `PATH` or gnu-sed. The file is rewritten atomically via temp file + rename,
/// preserving the original mode.
pub async fn replace_tag(file_path: &str, tag: &str, value: &str) -> AppResult<()> {
    let path = Path::new(file_path);
    let contents = fs::read_to_string(path).await?;

    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);

    let mut out = String::with_capacity(contents.len());
    let mut rest = contents.as_str();
    let mut replaced = 0usize;

    while let Some(start) = rest.find(&open) {
        let after_open = start + open.len();
        // Only rewrite a well-formed pair; a stray opening tag is left as-is.
        let Some(offset) = rest[after_open..].find(&close) else {
            break;
        };

        out.push_str(&rest[..after_open]);
        out.push_str(value);
        rest = &rest[after_open + offset..];
        replaced += 1;
    }
    out.push_str(rest);

    if replaced == 0 {
        warn!(
            "No <{}> element found in {}, leaving it unchanged",
            tag, file_path
        );
        return Ok(());
    }

    // Write atomically via a unique temp file + rename so an interrupted write
    // can't leave the config truncated and a stale temp file can't clobber the
    // target. The temp file inherits the target's permissions.
    let original_permissions = fs::metadata(path).await?.permissions();
    let tmp = unique_temp_path(path);
    let write = async {
        fs::write(&tmp, out.as_bytes()).await?;
        fs::set_permissions(&tmp, original_permissions).await?;
        fs::rename(&tmp, path).await
    }
    .await;
    if write.is_err() {
        let _ = fs::remove_file(&tmp).await;
    }
    write?;

    Ok(())
}

/// A unique temp path in the same directory as `path`, so the atomic rename
/// stays on the same filesystem and never clobbers an existing file.
fn unique_temp_path(path: &Path) -> std::path::PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(format!(".tmp.{}", rand::random::<u64>()));
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::replace_tag;
    use std::path::PathBuf;

    async fn with_file(contents: &str, name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("replace_tag_{}.xml", name));
        tokio::fs::write(&path, contents).await.unwrap();
        path
    }

    async fn run(contents: &str, name: &str) -> String {
        let path = with_file(contents, name).await;
        replace_tag(path.to_str().unwrap(), "agent_name", "new-name")
            .await
            .unwrap();
        let out = tokio::fs::read_to_string(&path).await.unwrap();
        tokio::fs::remove_file(&path).await.ok();
        out
    }

    #[tokio::test]
    async fn replaces_existing_value() {
        let out = run("<c><agent_name>old</agent_name></c>", "existing").await;
        assert_eq!(out, "<c><agent_name>new-name</agent_name></c>");
    }

    #[tokio::test]
    async fn fills_empty_element() {
        let out = run("<c><agent_name></agent_name></c>", "empty").await;
        assert_eq!(out, "<c><agent_name>new-name</agent_name></c>");
    }

    #[tokio::test]
    async fn replaces_every_occurrence() {
        let out = run(
            "<agent_name>a</agent_name>\n<x/>\n<agent_name>b</agent_name>",
            "multi",
        )
        .await;
        assert_eq!(
            out,
            "<agent_name>new-name</agent_name>\n<x/>\n<agent_name>new-name</agent_name>"
        );
    }

    #[tokio::test]
    async fn leaves_file_untouched_when_tag_absent() {
        let src = "<c><server>1.2.3.4</server></c>";
        assert_eq!(run(src, "absent").await, src);
    }

    #[tokio::test]
    async fn leaves_unclosed_tag_untouched() {
        let src = "<c><agent_name>oops</c>";
        assert_eq!(run(src, "unclosed").await, src);
    }

    #[tokio::test]
    async fn errors_when_file_missing() {
        let missing = std::env::temp_dir().join("replace_tag_does_not_exist.xml");
        assert!(
            replace_tag(missing.to_str().unwrap(), "agent_name", "x")
                .await
                .is_err()
        );
    }
}
