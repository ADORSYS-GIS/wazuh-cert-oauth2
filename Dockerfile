# syntax=docker/dockerfile:1.5

FROM rust:1 as base

LABEL maintainer="adorsys Cameroon"

ENV CARGO_TERM_COLOR=always

WORKDIR /app

FROM base as builder

# Install build dependencies for openssl-sys
RUN \
  --mount=type=cache,target=/var/cache/apt,sharing=locked \
  --mount=type=cache,target=/var/lib/apt,sharing=locked \
  apt-get update && \
  apt-get install -y --no-install-recommends pkg-config libssl-dev && \
  rm -rf /var/lib/apt/lists/*

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
  --mount=type=cache,target=/app/target \
  --mount=type=cache,target=/usr/local/cargo/registry/cache \
  --mount=type=cache,target=/usr/local/cargo/registry/index \
  --mount=type=cache,target=/usr/local/cargo/git/db \
  cargo build -p wazuh-cert-oauth2-server --profile prod --locked \
  && cp ./target/prod/wazuh-cert-oauth2-server server

FROM debian:12 as dep

RUN rm -f /etc/apt/apt.conf.d/docker-clean; echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

RUN \
  --mount=type=cache,target=/var/cache/apt,sharing=locked \
  --mount=type=cache,target=/var/lib/apt,sharing=locked \
  apt-get update \
  && apt-get install -y --no-install-recommends \
    gcc \
    ca-certificates \
    libssl3 \
  && rm -rf /var/lib/apt/lists/*


# Dependencies for libgcc
RUN \
  mkdir /deps && \
  cp /usr/lib/*-linux-gnu/libgcc_s.so.* /deps && \
  cp /usr/lib/*-linux-gnu/libssl.so.* /deps && \
  cp /usr/lib/*-linux-gnu/libcrypto.so.* /deps && \
  mkdir -p /deps/etc/ssl/certs && \
  cp /etc/ssl/certs/ca-certificates.crt /deps/etc/ssl/certs/ca-certificates.crt

FROM gcr.io/distroless/base-debian12:nonroot

LABEL maintainer="Stephane Segning <selastlambou@gmail.com>"
LABEL org.opencontainers.image.description="adorsys GIS Cameroon"

ENV RUST_LOG=warn
ENV PORT=8000

WORKDIR /app

COPY --from=builder /app/server /app/server
COPY --from=dep /deps /usr/lib/
COPY --from=dep /deps/etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

EXPOSE $PORT

ENTRYPOINT ["/app/server"]
