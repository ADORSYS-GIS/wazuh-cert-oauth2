# Getting Started

This guide walks you through setting up and running the `wazuh-cert-oauth2` project locally. There are two ways to run the stack — pick the one that fits your workflow:

| | [Option A: Docker Compose](#option-a-docker-compose-recommended) | [Option B: From Source](#option-b-running-from-source) |
| :--- | :--- | :--- |
| Best for | Quick setup, testing, demos | Active development, debugging |
| Requires | Docker & Docker Compose | Rust toolchain + build deps |
| Services managed | Automatically | Manually (3 separate processes) |

> Want to understand how the components fit together first? See the [Architecture Overview](./architecture.md).

---

## Prerequisites

### For Docker Compose (Option A)
- **Docker & Docker Compose**: Version 2.x or higher.
- **Git**: For cloning the repository.
- **OpenSSL**: To generate the Root CA.

### For From Source (Option B)
Everything above, plus:
- **Rust & Cargo**: Latest stable version — install via [rustup.rs](https://rustup.rs/).
- **Build dependencies**:
  - `openssl`
  - `musl-tools`
  - `build-essential`
  - `pkg-config`
  - `perl`

---

## Step 1: Generate the Root CA

This is required regardless of which option you choose. The Root CA is used to sign agent certificates.

Run these commands from the repository root:

```bash
openssl genrsa -out root-ca-key.pem 2048
openssl req -days 3650 -new -x509 -sha256 \
    -key root-ca-key.pem \
    -out root-ca.pem \
    -subj "/C=DE/L=Bayern/O=Adorsys/CN=root-ca"
```

You should now have `root-ca.pem` and `root-ca-key.pem` in the repository root. Both options below depend on these files.

---

## Option A: Docker Compose (Recommended)

The fastest way to get the full stack running. Docker Compose starts the Certificate Server, Webhook Proxy, and Keycloak together.

```bash
docker compose up -d --build
```

> [!TIP]
> On Linux, if your shell doesn't automatically export `UID`/`GID`, prefix the command to avoid permission issues with the mounted CA files:
> ```bash
> UID=$(id -u) GID=$(id -g) docker compose up -d --build
> ```

Wait about 30–60 seconds for Keycloak to fully boot. You can monitor progress with:

```bash
docker compose logs -f keycloak
```

### Running Services

| Service | URL | Credentials |
| :--- | :--- | :--- |
| Keycloak Admin Console | `http://localhost:9100/admin` | `admin` / `password` |
| Certificate Server API | `http://localhost:8000` | — |
| Webhook Proxy | `http://localhost:8100` | — |

> The Certificate Server and Webhook Proxy are used internally by the stack components and don't require direct interaction during normal usage.

### Enroll an Agent

With the stack running, use the client binary to enroll an agent. The Docker Compose setup pre-configures a test user and client in Keycloak:

- Test user: `test` / `test`
- OAuth2 client ID: `test-client` (public client, no secret needed)

Run the client from the repository root:

```bash
./target/release/wazuh-cert-oauth2-client oauth2 \
  --issuer http://localhost:9100/realms/dev \
  --client-id test-client \
  --endpoint http://localhost:8000/api/register-agent
```

> [!NOTE]
> If you haven't built the binaries yet, run `cargo build --release` first.

The client will attempt to open the authorization URL in your system's default browser automatically. If that fails, the URL will be printed in the terminal for you to open manually. Log in with `test` / `test`, and paste the authorization code back into the terminal. On success, the signed certificate and private key will be written to the platform-specific default path.

---

## Option B: Running from Source

Run each component individually — useful when you're actively developing or need to attach a debugger.

### 1. Build

```bash
cargo build --release
```

### 2. Start Keycloak (via Docker)

The server and webhook need an OIDC provider. The easiest way is to spin up just Keycloak from the Compose file:

```bash
docker compose up -d keycloak keycloak-config download-theme
```

Wait for Keycloak to be ready at `http://localhost:9100/admin` (creds: `admin` / `password`).

### 3. Run the Certificate Server

```bash
export RUST_LOG=info,rocket=warn,reqwest=warn

./target/release/wazuh-cert-oauth2-server \
  --oauth-issuer http://localhost:9100/realms/dev \
  --root-ca-path ./root-ca.pem \
  --root-ca-key-path ./root-ca-key.pem
```

Server listens on `http://localhost:8000`.

### 4. Run the Webhook Proxy

In a separate terminal:

```bash
export RUST_LOG=info,rocket=warn,reqwest=warn

./target/release/wazuh-cert-oauth2-webhook \
  --server-base-url http://localhost:8000 \
  --oauth-issuer http://localhost:9100/realms/dev \
  --oauth-client-id test-client-secret \
  --oauth-client-secret some-secret
```

Webhook proxy listens on `http://localhost:8100`.

### 5. Enroll an Agent

With the server and Keycloak running, enroll an agent using the pre-configured test client:

```bash
export RUST_LOG=info,reqwest=warn

./target/release/wazuh-cert-oauth2-client oauth2 \
  --issuer http://localhost:9100/realms/dev \
  --client-id test-client \
  --endpoint http://localhost:8000/api/register-agent
```

The client will attempt to open the authorization URL in your system's default browser automatically. If that fails, the URL will be printed in the terminal for you to open manually. Log in with `test` / `test`, and paste the authorization code back into the terminal.

---

## Configuration Reference

### Server Flags
| Flag | Env Variable | Default | Purpose |
| :--- | :--- | :--- | :--- |
| `--oauth-issuer` | `OAUTH_ISSUER` | (Required) | OIDC issuer URL. |
| `--root-ca-path` | `ROOT_CA_PATH` | (Required) | Path to Root CA cert (PEM). |
| `--root-ca-key-path` | `ROOT_CA_KEY_PATH` | (Required) | Path to Root CA key (PEM). |
| `--crl-path` | `CRL_PATH` | `/data/issuing.crl` | Path where CRL is written. |
| `--ledger-path` | `LEDGER_PATH` | `/data/ledger.csv` | Path to the issuance ledger. |

### Webhook Flags
| Flag | Env Variable | Default | Purpose |
| :--- | :--- | :--- | :--- |
| `--server-base-url` | `SERVER_BASE_URL` | (Required) | Base URL of the Certificate Server. |
| `--spool-dir` | `SPOOL_DIR` | `/data/spool` | Directory for persistent retry spooling. |
| `--oauth-client-id` | `OAUTH_CLIENT_ID` | (Required) | Client ID to talk to the Server. |
| `--oauth-client-secret` | `OAUTH_CLIENT_SECRET` | (Required) | Client Secret for the Server. |

### Client Flags
| Flag | Env Variable | Default | Purpose |
| :--- | :--- | :--- | :--- |
| `--issuer` | `ISSUER` | Keycloak URL | OIDC issuer for agent auth. |
| `--client-id` | `CLIENT_ID` | `adorsys-machine-client` | Agent's OAuth2 client ID. |
| `--endpoint` | `ENDPOINT` | registration URL | Server endpoint for CSR submission. |
| `--cert-path` | `CERT_PATH` | (Platform specific) | Destination for the signed cert. |

---

## Troubleshooting & Debugging

### 🌐 Connectivity Issues

#### "error sending request for url" (Client)
> [!IMPORTANT]
> **Symptom:** The client fails with an error similar to:  
> `An error occurred during execution: HTTP error: error sending request for url (http://localhost:9100/realms/dev/.well-known/openid-configuration)`

**Cause:** The OIDC provider (Keycloak) is not reachable from the client's network.  
**Solution:**
- Verify you can access `http://localhost:9100/realms/dev/.well-known/openid-configuration` in your browser.
- Ensure the `--issuer` URL matches the reachable address of your OIDC provider.

#### 401 Unauthorized or "Could not get JWKS" (Server)
> [!WARNING]
> **Symptom:** Server logs show `Could not get JWKS HTTP error: error sending request for url (...)` or the client receives a 401.

**Cause:** The Certificate Server cannot reach the OIDC issuer to validate tokens.  
**Solution:** When running in Docker, services must use internal service names. Ensure `OAUTH_ISSUER` in `compose.yaml` uses `http://keycloak:9100/...` instead of `localhost`.

---

### 🔑 Permissions & Security

#### "Permission Denied (os error 13)"
> [!CAUTION]
> **Symptom:** `CSR signing failed: I/O error: Permission denied (os error 13)` appears in logs.

**Cause:** The container user cannot read the host-mounted Root CA files.  
**Solution:**
- **Linux/macOS:** Run with explicit UID/GID: `UID=$(id -u) GID=$(id -g) docker compose up -d`
- **Windows (Docker Desktop):** Ensure Docker Desktop has permission to access the repository folder and the files aren't blocked by Windows Security.

#### "Executable file not found" (docker exec)
> [!NOTE]
> **Symptom:** `OCI runtime exec failed: ... exec: "ls": executable file not found in $PATH`

**Cause:** The project uses Distroless images — no shell or standard utilities.  
**Solution:**
1. Use `docker compose logs -f <service>` for debugging.
2. To inspect files, use the `ubuntu` sidecar service:
   ```bash
   docker compose exec ubuntu ls -R /data
   ```

---

### ⚙️ Infrastructure & Setup

#### keycloak-config "Restarting"
**Symptom:** The `keycloak-config` container shows `Restarting` for the first minute.  
**Cause:** It tries to configure Keycloak before it's fully booted.  
**Solution:** No action needed — it will succeed once Keycloak is ready.

#### Version/Help Flags not working
**Note:** If help and version flags don't exit correctly, rebuild the binaries with `cargo build --release`.
