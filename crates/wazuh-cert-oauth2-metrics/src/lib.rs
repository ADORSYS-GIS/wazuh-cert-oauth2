use once_cell::sync::Lazy;
use opentelemetry::KeyValue;
use opentelemetry::global;
use opentelemetry::metrics::{Counter, Histogram, Meter, UpDownCounter};
use std::path::Path;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn meter() -> Meter {
    global::meter("wazuh-cert-oauth2")
}

fn status_class(status: u16) -> &'static str {
    match status {
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "other",
    }
}

static HTTP_REQ_TOTAL: Lazy<Counter<u64>> =
    Lazy::new(|| meter().u64_counter("http_server_requests_total").build());

static HTTP_REQ_NON2XX_TOTAL: Lazy<Counter<u64>> = Lazy::new(|| {
    meter()
        .u64_counter("http_server_requests_non_2xx_total")
        .build()
});

static HTTP_REQ_DURATION: Lazy<Histogram<f64>> = Lazy::new(|| {
    meter()
        .f64_histogram("http_server_request_duration_seconds")
        .build()
});

static HTTP_REQ_PARAMS_TOTAL: Lazy<Counter<u64>> = Lazy::new(|| {
    meter()
        .u64_counter("http_server_request_params_total")
        .build()
});

// Spool counters
static SPOOL_ENQ_TOTAL: Lazy<Counter<u64>> =
    Lazy::new(|| meter().u64_counter("spool_enqueue_total").build());
static SPOOL_DEQ_TOTAL: Lazy<Counter<u64>> =
    Lazy::new(|| meter().u64_counter("spool_dequeue_total").build());
static SPOOL_CANCEL_TOTAL: Lazy<Counter<u64>> =
    Lazy::new(|| meter().u64_counter("spool_cancel_pending_total").build());

// Spool "gauges" implemented as up-down counters + histogram for age
static SPOOL_DEPTH_UDC: Lazy<UpDownCounter<i64>> =
    Lazy::new(|| meter().i64_up_down_counter("spool_queue_depth").build());
static SPOOL_DEPTH_LAST: AtomicI64 = AtomicI64::new(0);

static SPOOL_OLDEST_AGE_HIST: Lazy<Histogram<f64>> =
    Lazy::new(|| meter().f64_histogram("spool_oldest_age_seconds").build());

pub fn record_http_request(route: &str, method: &str, status: u16, duration_seconds: f64) {
    let attrs = [
        KeyValue::new("route", route.to_string()),
        KeyValue::new("method", method.to_string()),
        KeyValue::new("status_class", status_class(status).to_string()),
    ];
    HTTP_REQ_TOTAL.add(1, &attrs);
    if !(200..=299).contains(&status) {
        HTTP_REQ_NON2XX_TOTAL.add(1, &attrs);
    }
    let attrs2 = [
        KeyValue::new("route", route.to_string()),
        KeyValue::new("method", method.to_string()),
    ];
    HTTP_REQ_DURATION.record(duration_seconds, &attrs2);
}

pub fn record_http_params(route: &str, method: &str, has_subject: bool, has_serial: bool) {
    HTTP_REQ_PARAMS_TOTAL.add(
        1,
        &[
            KeyValue::new("route", route.to_string()),
            KeyValue::new("method", method.to_string()),
            KeyValue::new("has_subject", has_subject.to_string()),
            KeyValue::new("has_serial", has_serial.to_string()),
        ],
    );
}

pub fn inc_spool_enqueued(reason: &str, count: u64) {
    SPOOL_ENQ_TOTAL.add(count, &[KeyValue::new("reason", reason.to_string())]);
}

pub fn inc_spool_dequeued(outcome: &str, count: u64) {
    SPOOL_DEQ_TOTAL.add(count, &[KeyValue::new("outcome", outcome.to_string())]);
}

pub fn inc_spool_canceled(count: u64) {
    SPOOL_CANCEL_TOTAL.add(count, &[]);
}

pub fn update_spool_gauges(spool_dir: &Path) {
    let mut depth: i64 = 0;
    let mut oldest_secs: i64 = 0;
    if let Ok(rd) = std::fs::read_dir(spool_dir) {
        let mut oldest_millis: Option<u128> = None;
        for entry in rd.flatten() {
            let p = entry.path();
            if p.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            depth += 1;
            if let Ok(md) = entry.metadata()
                && let Ok(mtime) = md.modified()
                && let Ok(d) = mtime.duration_since(UNIX_EPOCH)
            {
                let ms = d.as_millis();
                oldest_millis = Some(oldest_millis.map_or(ms, |cur| cur.min(ms)));
            }
        }
        if let Some(ms) = oldest_millis
            && let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH)
        {
            let now_ms = now.as_millis();
            oldest_secs = (now_ms.saturating_sub(ms) as u64 / 1000) as i64;
        }
    }
    let prev = SPOOL_DEPTH_LAST.swap(depth, Ordering::Relaxed);
    let delta = depth.saturating_sub(prev);
    let attrs: &[KeyValue] = &[];
    if delta != 0 {
        SPOOL_DEPTH_UDC.add(delta, attrs);
    }
    SPOOL_OLDEST_AGE_HIST.record(oldest_secs as f64, attrs);
}
