use rocket::fairing::{Fairing, Info, Kind};
use rocket::{Data, Request, Response};
use std::time::Instant;
use tracing::info;
use wazuh_cert_oauth2_metrics::record_http_request;

pub struct TelemetryFairing;

#[rocket::async_trait]
impl Fairing for TelemetryFairing {
    fn info(&self) -> Info {
        Info {
            name: "otel_request_span",
            kind: Kind::Request | Kind::Response,
        }
    }

    async fn on_request(&self, req: &mut Request<'_>, _: &mut Data<'_>) {
        let method = req.method().as_str().to_string();
        let path = req.uri().path().to_string();
        let remote = req.client_ip().map(|ip| ip.to_string());
        let _span = tracing::info_span!(
            "http.request",
            http.method = %method,
            http.target = %path,
            net.peer_ip = remote.as_deref().unwrap_or("")
        );
        info!(target: "http", method = %method, path = %path, "request start");
        req.local_cache(Instant::now);
    }

    async fn on_response<'r>(&self, req: &'r Request<'_>, res: &mut Response<'r>) {
        // Metrics from fairing
        let status = res.status();
        let start = req.local_cache(Instant::now);
        let dur = start.elapsed();
        let method = req.method().as_str();
        let route = req
            .route()
            .map(|r| r.uri.path())
            .unwrap_or_else(|| req.uri().path().as_str());
        record_http_request(route, method, status.code, dur.as_secs_f64());
    }
}

pub fn telemetry_fairing() -> TelemetryFairing {
    TelemetryFairing
}
