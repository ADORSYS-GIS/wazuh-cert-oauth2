# syntax=docker/dockerfile:1.5

FROM rust:1 as base

LABEL maintainer="adorsys Cameroon"

ENV CARGO_TERM_COLOR=always
ENV OPENSSL_STATIC=1

WORKDIR /app

FROM base as builder

ARG TARGETARCH

# Install toolchain and dependencies for static musl builds with vendored OpenSSL
RUN \
  --mount=type=cache,target=/var/cache/apt,sharing=locked \
  --mount=type=cache,target=/var/lib/apt,sharing=locked \
  apt-get update && \
  apt-get install -y --no-install-recommends \
    musl-tools \
    build-essential \
    pkg-config \
    perl \
  && rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl

RUN \
  # Mount workspace files and only the necessary crates
  --mount=type=bind,source=./Cargo.toml,target=/app/Cargo.toml \
  --mount=type=bind,source=./Cargo.lock,target=/app/Cargo.lock \
  --mount=type=bind,source=./crates/wazuh-cert-oauth2-server/Cargo.toml,target=/app/crates/wazuh-cert-oauth2-server/Cargo.toml \
  --mount=type=bind,source=./crates/wazuh-cert-oauth2-server/Rocket.toml,target=/app/crates/wazuh-cert-oauth2-server/Rocket.toml \
  --mount=type=bind,source=./crates/wazuh-cert-oauth2-server/src,target=/app/crates/wazuh-cert-oauth2-server/src \
  --mount=type=bind,source=./crates/wazuh-cert-oauth2-model/Cargo.toml,target=/app/crates/wazuh-cert-oauth2-model/Cargo.toml \
  --mount=type=bind,source=./crates/wazuh-cert-oauth2-model/src,target=/app/crates/wazuh-cert-oauth2-model/src \
  --mount=type=bind,source=./crates/wazuh-cert-oauth2-client/Cargo.toml,target=/app/crates/wazuh-cert-oauth2-client/Cargo.toml \
  --mount=type=bind,source=./crates/wazuh-cert-oauth2-client/src,target=/app/crates/wazuh-cert-oauth2-client/src \
  --mount=type=bind,source=./crates/wazuh-cert-oauth2-webhook/Cargo.toml,target=/app/crates/wazuh-cert-oauth2-webhook/Cargo.toml \
  --mount=type=bind,source=./crates/wazuh-cert-oauth2-webhook/src,target=/app/crates/wazuh-cert-oauth2-webhook/src \
  --mount=type=bind,source=./crates/wazuh-cert-oauth2-metrics/Cargo.toml,target=/app/crates/wazuh-cert-oauth2-metrics/Cargo.toml \
  --mount=type=bind,source=./crates/wazuh-cert-oauth2-metrics/src,target=/app/crates/wazuh-cert-oauth2-metrics/src \
  --mount=type=bind,source=./crates/wazuh-cert-oauth2-healthcheck/Cargo.toml,target=/app/crates/wazuh-cert-oauth2-healthcheck/Cargo.toml \
  --mount=type=bind,source=./crates/wazuh-cert-oauth2-healthcheck/src,target=/app/crates/wazuh-cert-oauth2-healthcheck/src \
  --mount=type=bind,source=./crates/wazuh-cert-oauth2-webhook/Rocket.toml,target=/app/crates/wazuh-cert-oauth2-webhook/Rocket.toml \
  --mount=type=cache,target=/app/target \
  --mount=type=cache,target=/usr/local/cargo/registry/cache \
  --mount=type=cache,target=/usr/local/cargo/registry/index \
  --mount=type=cache,target=/usr/local/cargo/git/db \
  case "$TARGETARCH" in \
    "amd64") \
      export RUST_TARGET=x86_64-unknown-linux-musl; \
      export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc; \
      ;; \
    "arm64") \
      export RUST_TARGET=aarch64-unknown-linux-musl; \
      export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc; \
      ;; \
    *) \
      echo "Unsupported TARGETARCH: $TARGETARCH"; \
      exit 1; \
      ;; \
  esac; \
  cargo build --profile prod --locked \
    --target "${RUST_TARGET}" \
    -p wazuh-cert-oauth2-server \
    -p wazuh-cert-oauth2-webhook \
    -p wazuh-cert-oauth2-healthcheck \
    --features openssl/vendored \
  && cp ./target/"${RUST_TARGET}"/prod/wazuh-cert-oauth2-server server \
  && cp ./target/"${RUST_TARGET}"/prod/wazuh-cert-oauth2-webhook webhook \
  && cp ./target/"${RUST_TARGET}"/prod/wazuh-cert-oauth2-healthcheck healthcheck

FROM gcr.io/distroless/static-debian12:nonroot as webhook

LABEL maintainer="Stephane Segning <selastlambou@gmail.com>"
LABEL org.opencontainers.image.description="adorsys GIS Cameroon"

ENV RUST_LOG=warn
ENV PORT=8000

WORKDIR /app

COPY --from=builder /app/webhook /app/webhook
COPY --from=builder /app/healthcheck /app/healthcheck

USER nonroot:nonroot

EXPOSE $PORT

HEALTHCHECK --interval=10s --timeout=3s --start-period=2s --retries=5 CMD ["/app/healthcheck"]

ENTRYPOINT ["/app/webhook"]

FROM gcr.io/distroless/static-debian12:nonroot as oauth2

LABEL maintainer="Stephane Segning <selastlambou@gmail.com>"
LABEL org.opencontainers.image.description="adorsys GIS Cameroon"

ENV RUST_LOG=warn
ENV PORT=8000

WORKDIR /app

COPY --from=builder /app/server /app/server
COPY --from=builder /app/healthcheck /app/healthcheck

USER nonroot:nonroot

EXPOSE $PORT

HEALTHCHECK --interval=10s --timeout=3s --start-period=2s --retries=5 CMD ["/app/healthcheck"]

ENTRYPOINT ["/app/server"]
