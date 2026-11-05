use std::process::Command;

/// The client must terminate with a non-zero exit code when enrollment fails
/// (e.g. the issuer is unreachable), so callers and wrappers can detect the
/// failure from the process exit status.
#[test]
fn exits_nonzero_when_enrollment_fails() {
    let bin = env!("CARGO_BIN_EXE_wazuh-cert-oauth2-client");

    let output = Command::new(bin)
        .args([
            "o-auth2",
            // Unreachable issuer: the discovery-document fetch fails before any
            // agent control runs, so this is safe and deterministic.
            "--issuer",
            "http://127.0.0.1:1/realms/nonexistent",
            "--agent-control=false",
        ])
        .output()
        .expect("failed to run client binary");

    assert!(
        !output.status.success(),
        "expected non-zero exit code, got success"
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "expected exit code 1 on enrollment failure"
    );
}
