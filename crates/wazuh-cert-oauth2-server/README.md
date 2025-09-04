# Wazuh Cert OAuth2 Server

Version: 0.2.19

## Overview

The Wazuh Cert OAuth2 Server is a Rust-based web application built with Rocket. It acts as a simple Certificate
Authority (CA) to issue client certificates for Wazuh agents. This server is designed to work in conjunction with the
`wazuh-cert-oauth2-client`.

The server's primary responsibilities are:

1. To expose an API endpoint (`/api/register-agent`) that, upon receiving a valid JWT (obtained by the client via an
   OAuth2/OIDC flow), generates a new X.509 client certificate and private key.
2. The Common Name (CN) of the issued certificate is derived from the `sub` (subject) claim of the validated JWT.
3. To sign these client certificates using a pre-configured root CA certificate and key.
4. To provide a health check endpoint (`/health`).

## Features

- Acts as a simple CA for issuing Wazuh agent client certificates.
- Secure API endpoint for agent registration, protected by JWT authentication.
- Dynamic certificate generation based on JWT claims.
- Uses OpenSSL for cryptographic operations.
- Built with the Rocket web framework for Rust.
- Configurable via environment variables and a `Rocket.toml` file.
- Fetches and caches JWKS from an OIDC provider for JWT validation.
- Supports TLS for secure communication (configurable via `Rocket.toml` or code).

## Prerequisites

- Rust toolchain (latest stable recommended).
- An OAuth2/OIDC provider for issuing JWTs that the server will validate.
- A Root CA certificate (`root-ca.pem`) and its corresponding private key (`root-ca-key.pem`). You will need to generate
  these or use existing ones.

## Building

```bash
cargo build --release
```

The executable will be located at `target/release/wazuh-cert-oauth2`.

## Configuration

The server is configured through environment variables and a [`Rocket.toml`](Rocket.toml:0) file.

### Environment Variables

Key environment variables are typically defined in a `.env` file (see [`.env.example`](.env:0) or the provided `.env`):

- `RUST_LOG`: Log level (e.g., `info`, `debug`).
    - Default: `info`
- `OAUTH_ISSUER`: (Required) The URL of the OAuth2/OIDC provider (e.g., `https://your-oidc-provider.com`). This is used
  to fetch the OIDC discovery document and subsequently the JWKS.
- `KC_AUDIENCES`: (Required) A comma-separated list of audiences that are considered valid for incoming JWTs (e.g.,
  `api://your-api,another-audience`).
    - Default: `account`
- `ROOT_CA_PATH`: (Required) Path to the root CA certificate file (PEM format, e.g., `conf/root-ca.pem`).
- `ROOT_CA_KEY_PATH`: (Required) Path to the root CA private key file (PEM format, e.g., `conf/root-ca-key.pem`).

### `Rocket.toml`

This file configures the Rocket framework. See [`Rocket.toml`](Rocket.toml:0) for an example.

- **Address & Port**: Configures the listening address and port (e.g., `0.0.0.0:8000`).
- **TLS**: Rocket can be configured for TLS. By default, the [`Cargo.toml`](Cargo.toml:0) specifies paths for
  `tls.certs` and `tls.key`. You can override these in `Rocket.toml` or ensure the files exist at the specified paths.
  ```toml
  [default.tls]
  certs = "path/to/your/server.crt"
  key = "path/to/your/server.key"
  ```

### Root CA Setup

You must provide your own root CA certificate and private key.

1. Generate or obtain a root CA certificate (`root-ca.pem`) and its private key (`root-ca-key.pem`).
2. Place these files in a secure location accessible by the server.
3. Set the `ROOT_CA_PATH` and `ROOT_CA_KEY_PATH` environment variables to point to these files.

**Example (using OpenSSL to generate a self-signed root CA):**

```bash
# Generate root CA private key
openssl genpkey -algorithm RSA -out root-ca-key.pem -pkeyopt rsa_keygen_bits:4096

# Generate root CA certificate (self-signed)
openssl req -x509 -new -nodes -key root-ca-key.pem -sha256 -days 1825 -out root-ca.pem \
    -subj "/CN=MyWazuhOAuthRootCA"
```

Store `root-ca-key.pem` and `root-ca.pem` securely and update the environment variables.

## API Endpoints

### Health Check

- **Endpoint**: `GET /health`
- **Description**: Returns the health status of the server.
- **Response**:
    - `200 OK`: `{"status": "ok"}`

### Register Agent

- **Endpoint**: `POST /api/register-agent`
- **Description**: Registers a new agent by generating and returning a client certificate and private key.
- **Authentication**: Requires a valid Bearer JWT in the `Authorization` header. The JWT is validated against the JWKS
  fetched from the `OAUTH_ISSUER` and must match one of the `KC_AUDIENCES`.
- **Request Body**: `application/json`
  ```json
  {
      // Currently, the DTO (RegisterAgentDto) fields are not actively used by the cert generation logic,
      // but the structure is defined in wazuh-cert-oauth2-model.
      // Example:
      // "hostname": "agent01.example.com"
  }
  ```
  *(Note: The `RegisterAgentDto` is passed to the certificate generation function but its fields are not currently
  utilized in `shared/certs.rs` as of version 0.2.19. The certificate CN is derived from the JWT `sub` claim.)*
- **Response**: `application/json`
    - `200 OK`: [`UserKey`](../wazuh-cert-oauth2-model/src/models/user_key.rs:0)
      ```json
      {
          "public_key": "-----BEGIN CERTIFICATE-----\nMIIC...=\n-----END CERTIFICATE-----\n",
          "private_key": "-----BEGIN PRIVATE KEY-----\nMIIJ...=\n-----END PRIVATE KEY-----\n"
      }
      ```
    - `401 Unauthorized`: If JWT is missing, invalid, or does not meet audience criteria.
    - `500 Internal Server Error`: If certificate generation fails.

## Security

- **JWT Authentication**: API endpoints (specifically `/api/register-agent`) are protected using JWT authentication. The
  server fetches JWKS from the configured OIDC provider to validate token signatures.
- **TLS**: It is highly recommended to run this server over TLS. Configure TLS via `Rocket.toml` or a reverse proxy.
- **CA Key Security**: The private key of the root CA (`ROOT_CA_KEY_PATH`) is critical. Protect it appropriately.

## Key Dependencies

- [`rocket`](https://crates.io/crates/rocket): Web framework.
- [`tokio`](https://crates.io/crates/tokio): Asynchronous runtime.
- [`anyhow`](https://crates.io/crates/anyhow): Flexible error handling.
- [`thiserror`](https://crates.io/crates/thiserror): Error derive macro.
- [`env_logger`](https://crates.io/crates/env_logger): Logging.
- [`jsonwebtoken`](https://crates.io/crates/jsonwebtoken): JWT validation (via model).
- [`openssl`](https://crates.io/crates/openssl): Cryptographic operations for certificate generation.
- [`wazuh-cert-oauth2-model`](../wazuh-cert-oauth2-model): Shared data models and services.

This README provides a comprehensive guide for the `wazuh-cert-oauth2` server.