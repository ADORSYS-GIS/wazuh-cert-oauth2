FROM rust:1 as base

LABEL maintainer="adorsys Cameroon"

ENV CARGO_TERM_COLOR=always

WORKDIR /app

FROM base as builder

RUN \
  --mount=type=bind,source=./wazuh-cert-oauth2/Cargo.lock,target=/app/wazuh-cert-oauth2/Cargo.lock \
  --mount=type=bind,source=./wazuh-cert-oauth2/Cargo.toml,target=/app/wazuh-cert-oauth2/Cargo.toml \
  --mount=type=bind,source=./wazuh-cert-oauth2/Rocket.toml,target=/app/wazuh-cert-oauth2/Rocket.toml \
  --mount=type=bind,source=./wazuh-cert-oauth2/src,target=/app/wazuh-cert-oauth2/src \
    #
  --mount=type=bind,source=./wazuh-cert-oauth2-model/Cargo.lock,target=/app/wazuh-cert-oauth2-model/Cargo.lock \
  --mount=type=bind,source=./wazuh-cert-oauth2-model/Cargo.toml,target=/app/wazuh-cert-oauth2-model/Cargo.toml \
  --mount=type=bind,source=./wazuh-cert-oauth2-model/src,target=/app/wazuh-cert-oauth2-model/src \
    #
  #--mount=type=cache,target=/app/wazuh-cert-oauth2/target \
  --mount=type=cache,target=/app/wazuh-cert-oauth2-model/target \
    #
  --mount=type=cache,target=/usr/local/cargo/registry/cache \
  --mount=type=cache,target=/usr/local/cargo/registry/index \
  --mount=type=cache,target=/usr/local/cargo/git/db \
    #
  cargo build --manifest-path wazuh-cert-oauth2/Cargo.toml --release --locked \
    #
  && cp ./wazuh-cert-oauth2/target/release/wazuh-cert-oauth2 server

FROM debian:12 as dep

RUN rm -f /etc/apt/apt.conf.d/docker-clean; echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

RUN \
  --mount=type=cache,target=/var/cache/apt,sharing=locked \
  --mount=type=cache,target=/var/lib/apt,sharing=locked \
  #  
  apt-get update \
  #
  && apt-get install -y gcc --no-install-recommends 


# Dependencies for libgcc
RUN \
     --mount=type=cache,target=/usr/lib/*-linux-gnu \
  #
  mkdir /deps && \
  #
  cp /usr/lib/*-linux-gnu/libgcc_s.so.* /deps

FROM gcr.io/distroless/base-debian12:nonroot

LABEL maintainer="stephane.segning-lambou@adorsys.com"
LABEL org.opencontainers.image.description="adorsys Cameroon"

ENV RUST_LOG=warn
ENV PORT=8000

WORKDIR /app

COPY --from=builder /app/server /app/server
COPY --from=dep /deps /usr/lib/

EXPOSE $PORT

ENTRYPOINT ["/app/server"]