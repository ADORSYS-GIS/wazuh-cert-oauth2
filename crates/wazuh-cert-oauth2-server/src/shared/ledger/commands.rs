// Commands for the ledger worker loop

use wazuh_cert_oauth2_model::models::errors::AppResult;

pub(super) enum Command {
    RecordIssued {
        subject: String,
        serial_hex: String,
        issued_at_unix: u64,
        respond_to: tokio::sync::oneshot::Sender<AppResult<()>>,
    },
    MarkRevoked {
        serial_hex: String,
        reason: Option<String>,
        revoked_at_unix: u64,
        respond_to: tokio::sync::oneshot::Sender<AppResult<()>>,
    },
}
