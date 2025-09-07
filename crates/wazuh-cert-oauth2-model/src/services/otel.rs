use crate::models::errors::AppResult;
use opentelemetry::global;
use opentelemetry::trace::TracerProvider;
use opentelemetry_otlp::{Compression, Protocol, SpanExporter, WithExportConfig, WithTonicConfig};
use std::time::Duration;
use tracing_opentelemetry::{MetricsLayer, OpenTelemetryLayer};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;

#[inline]
pub fn init_tracer_provider(
    service_name: &str,
) -> AppResult<opentelemetry_sdk::trace::SdkTracerProvider> {
    let exporter = SpanExporter::builder()
        .with_tonic()
        .with_compression(Compression::Gzip)
        .with_timeout(Duration::from_secs(3))
        .build()?;

    let resource = opentelemetry_sdk::Resource::builder()
        .with_service_name(service_name.to_string())
        .build();

    let tracer_provider = opentelemetry_sdk::trace::TracerProviderBuilder::default()
        .with_batch_exporter(exporter)
        .with_sampler(opentelemetry_sdk::trace::Sampler::AlwaysOn)
        .with_id_generator(opentelemetry_sdk::trace::RandomIdGenerator::default())
        .with_max_events_per_span(16)
        .with_max_attributes_per_span(16)
        .with_resource(resource)
        .build();

    global::set_tracer_provider(tracer_provider.clone());

    Ok(tracer_provider)
}

pub fn init_meter_provider(
    service_name: &str,
) -> AppResult<opentelemetry_sdk::metrics::SdkMeterProvider> {
    let exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_temporality(opentelemetry_sdk::metrics::Temporality::default())
        .with_tonic()
        .with_compression(Compression::Gzip)
        .with_protocol(Protocol::Grpc)
        .with_timeout(Duration::from_secs(3))
        .build()?;

    let reader = opentelemetry_sdk::metrics::PeriodicReader::builder(exporter)
        .with_interval(Duration::from_secs(3))
        .build();

    let meter_provider = opentelemetry_sdk::metrics::SdkMeterProvider::builder()
        .with_reader(reader)
        .with_resource(
            opentelemetry_sdk::Resource::builder()
                .with_service_name(service_name.to_string())
                .build(),
        )
        .build();

    global::set_meter_provider(meter_provider.clone());

    Ok(meter_provider)
}

/// Set up global subscriber. For now we set a simple env-filter subscriber so
/// logs/traces are routed through tracing without an OpenTelemetry exporter.
/// Replace with an OTLP + tracing integration during a proper port.
pub fn setup_telemetry(service_name: &str) -> AppResult<()> {
    let tracer_provider = init_tracer_provider(service_name)?;
    let meter_provider = init_meter_provider(service_name)?;

    let tracer = tracer_provider.tracer("trace_subscriber");

    let subscriber = tracing_subscriber::registry()
        .with(EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .with(MetricsLayer::new(meter_provider.clone()))
        .with(OpenTelemetryLayer::new(tracer));

    tracing::subscriber::set_global_default(subscriber)?;

    Ok(())
}
