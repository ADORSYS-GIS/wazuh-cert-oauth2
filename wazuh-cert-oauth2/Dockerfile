FROM rust as base

WORKDIR /app

FROM base as builder

# Copy the Cargo.toml and Cargo.lock files to cache dependencies
COPY ./ ./

# Build the dependencies
RUN cargo build --release

FROM base

WORKDIR /app

COPY --from=builder /app/target/release/wazuh-cert-oauth2 /app/wazuh-cert-oauth2

CMD ["/app/wazuh-cert-oauth2"]