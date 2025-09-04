# Wazuh Cert OAuth2 Client

Version: 0.2.19

## Overview

The Wazuh Cert OAuth2 Client is a command-line application designed to facilitate the registration of Wazuh agents by obtaining client certificates through an OAuth2/OpenID Connect (OIDC) flow. It interacts with a corresponding `wazuh-cert-oauth2` server component, which acts as a simple Certificate Authority (CA) to issue these certificates.

The client performs the following key operations:
1.  Authenticates with an OIDC provider using a configured OAuth2 flow (supports standard and service account flows).
2.  Retrieves an access token.
3.  Uses the access token to request a new client certificate and private key from the `wazuh-cert-oauth2` server.
4.  Saves the received certificate and key to local files.
5.  Configures the local Wazuh agent with the new certificate, key, and agent name (derived from the token claims).
6.  Manages the Wazuh agent service (stop/restart) during the process.

## Features

-   OAuth2/OIDC authentication for secure agent registration.
-   Support for standard OAuth2 flows and service account authentication.
-   Automated fetching and validation of OIDC discovery documents and JWKS.
-   Secure retrieval and local storage of agent certificates and private keys.
-   Automatic configuration of Wazuh agent name based on token claims.
-   Integration with local Wazuh agent service management.
-   Cross-compilation support for Linux (x86_64, aarch64).
-   Configurable via command-line arguments and environment variables.

## Prerequisites

-   Rust toolchain (latest stable recommended).
-   Access to an OAuth2/OIDC provider.
-   A running instance of the `wazuh-cert-oauth2` server.
-   A local Wazuh agent installation (if managing agent services).
-   For cross-compilation: Docker or a compatible container runtime with `cross` installed (`cargo install cross`). `libssl-dev` is required for the target architecture (handled by `Cross.toml` for specified targets).

## Building

### Standard Build

```bash
cargo build --release
```
The executable will be located at `target/release/wazuh-cert-oauth2-client`.

### Cross-Compilation

This project uses `cross` for cross-compilation. The following targets are pre-configured in [`Cross.toml`](Cross.toml:1):
- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`

To cross-compile for a specific target (e.g., `x86_64-unknown-linux-gnu`):
```bash
cross build --target x86_64-unknown-linux-gnu --release
```
The executable will be in `target/x86_64-unknown-linux-gnu/release/wazuh-cert-oauth2-client`.

The `Cross.toml` includes pre-build steps to install `libssl-dev` for the Linux targets.

## Configuration

The client can be configured via command-line arguments and environment variables. CLI arguments take precedence.

### Command-Line Arguments

Run `wazuh-cert-oauth2-client --help` for a full list of options. Key arguments include:

-   `--issuer <OAUTH2_ISSUER_URL>`: (Required) The URL of the OAuth2/OIDC provider.
    -   Env: `OAUTH2_ISSUER`
-   `--audience <OAUTH2_AUDIENCE>`: (Required) The audience for the OAuth2 token. Can be specified multiple times.
    -   Env: `OAUTH2_AUDIENCE` (comma-separated string)
-   `--client-id <OAUTH2_CLIENT_ID>`: (Required) The OAuth2 client ID.
    -   Env: `OAUTH2_CLIENT_ID`
-   `--client-secret <OAUTH2_CLIENT_SECRET>`: The OAuth2 client secret (required for some flows).
    -   Env: `OAUTH2_CLIENT_SECRET`
-   `--endpoint <WAZUH_CERT_OAUTH2_SERVER_URL>`: (Required) The base URL of the `wazuh-cert-oauth2` server (e.g., `https://your-server.com/api/register-agent`).
    -   Env: `ENDPOINT_URL`
-   `--cert-path <PATH>`: Path to save the agent certificate.
    -   Default: `/var/ossec/etc/sslmanager/ssl.cert`
    -   Env: `CERT_PATH`
-   `--key-path <PATH>`: Path to save the agent private key.
    -   Default: `/var/ossec/etc/sslmanager/ssl.key`
    -   Env: `KEY_PATH`
-   `--is-service-account`: Flag to indicate if using a service account flow (e.g., client credentials).
    -   Env: `IS_SERVICE_ACCOUNT` (set to `true` or `false`)
-   `--root-ca <PATH_TO_ROOT_CA_PEM>`: Path to the root CA certificate (PEM format) for verifying the `wazuh-cert-oauth2` server's TLS certificate.
    -   Env: `ROOT_CA_PATH`
-   `--skip-hostname-verification`: Skip TLS hostname verification when connecting to the `wazuh-cert-oauth2` server (use with caution).
    -   Env: `SKIP_HOSTNAME_VERIFICATION` (set to `true` or `false`)
-   `--skip-local-agent-management`: Skip stopping/restarting/setting name for the local Wazuh agent.
    -   Env: `SKIP_LOCAL_AGENT_MANAGEMENT` (set to `true` or `false`)

### Environment Variables

(As listed above, corresponding to CLI arguments)

## Usage / Workflow

1.  Ensure the `wazuh-cert-oauth2` server is running and accessible.
2.  Ensure your OAuth2/OIDC provider is configured with the necessary client credentials and redirect URIs (if applicable for the chosen flow).
3.  Execute the client with the required arguments or environment variables:

    ```bash
    # Example using CLI arguments for a standard flow
    ./target/release/wazuh-cert-oauth2-client \
        --issuer https://your-oidc-provider.com \
        --audience api://your-api \
        --client-id your_client_id \
        --endpoint https://your-wazuh-cert-server.com/api/register-agent

    # Example using environment variables and service account flow
    export OAUTH2_ISSUER="https://your-oidc-provider.com"
    export OAUTH2_AUDIENCE="api://your-api"
    export OAUTH2_CLIENT_ID="your_client_id"
    export OAUTH2_CLIENT_SECRET="your_client_secret"
    export ENDPOINT_URL="https://your-wazuh-cert-server.com/api/register-agent"
    export IS_SERVICE_ACCOUNT="true"
    ./target/release/wazuh-cert-oauth2-client
    ```

The client will guide you through the OAuth2 authorization process if user interaction is required (e.g., device flow, authorization code flow). Upon successful authentication and certificate retrieval:
-   The agent certificate will be saved to `cert-path`.
-   The agent private key will be saved to `key-path`.
-   If local agent management is not skipped:
    -   The Wazuh agent will be stopped.
    -   The agent name will be set based on the `name` claim in the token.
    -   The Wazuh agent will be restarted.

## Key Dependencies

-   [`tokio`](https://crates.io/crates/tokio): Asynchronous runtime.
-   [`anyhow`](https://crates.io/crates/anyhow): Flexible error handling.
-   [`log`](https://crates.io/crates/log) & [`env_logger`](https://crates.io/crates/env_logger): Logging.
-   [`structopt`](https://crates.io/crates/structopt): Command-line argument parsing.
-   [`oauth2`](https://crates.io/crates/oauth2): OAuth2 client implementation.
-   [`reqwest`](https://crates.io/crates/reqwest): HTTP client.
-   [`wazuh-cert-oauth2-model`](../wazuh-cert-oauth2-model): Shared data models and services.
-   [`jsonwebtoken`](https://crates.io/crates/jsonwebtoken): JWT validation (via model).

This README provides a comprehensive guide for the `wazuh-cert-oauth2-client`.