FROM rust as base

LABEL maintainer="adorsys Cameroon"

WORKDIR /app

FROM base as builder

COPY ./ ./

RUN cargo build --manifest-path wazuh-cert-oauth2/Cargo.toml --release

FROM base

WORKDIR /app

COPY --from=builder /app/wazuh-cert-oauth2/target/release/wazuh-cert-oauth2 /app/wazuh-cert-oauth2

EXPOSE 8000

CMD ["/app/wazuh-cert-oauth2"]