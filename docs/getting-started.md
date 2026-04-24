# Getting Started

This guide covers the prerequisites, dependencies, and steps to get the `wazuh-cert-oauth2` project running locally.

> [!NOTE]
> **GitHub Integration**: The Webhook Proxy supports automated GitHub issue creation for new user registrations in Keycloak. To use this feature, you will need a GitHub Personal Access Token (preferably a **fine-grained** token with only **Issue Creation** permissions), the repository owner, and the repository name. See the [Configuration Reference](#webhook-flags) for details.

## Prerequisites

Before building or running the project, ensure you have the following installed:

- **Rust & Cargo**: Latest stable version. Install via [rustup.rs](https://rustup.rs/).
- **Docker & Docker Compose**: Version 2.x or higher.
- **Git**: For cloning the repository.
- **Build time dependencies**: 
    - openssl
    - musl-tools
    - build-essential
    - pkg-config
    - perl

---

## Setup: Generate Root CA

The system requires a Root CA certificate and key to sign agent requests. This must be generated **before** running Docker Compose or the local server.

Run the following commands in the root of the repository:

```bash
echo "Generating Root CA"
openssl genrsa -out root-ca-key.pem 2048
openssl req -days 3650 -new -x509 -sha256 \
    -key root-ca-key.pem \
    -out root-ca.pem \
    -subj "/C=DE/L=Bayern/O=Adorsys/CN=root-ca"
```

---

## 1. Running with Docker Compose (Recommended)

Once the `root-ca.pem` and `root-ca-key.pem` files are in the repository root, you can start the full stack.

```bash
docker compose up -d --build
```

### Key Components:
- **Server API**: `http://localhost:8000`
- **Webhook Proxy**: `http://localhost:8100`
- **Keycloak**: `http://localhost:9100/admin` (Creds: `admin/password`)

---

## 2. Running Locally from Source

If you prefer to run the components individually for development.

### Build the project
```bash
cargo build --release
```

### Run the Server
```bash
export RUST_LOG=info,rocket=warn,reqwest=warn

./target/release/wazuh-cert-oauth2-server \
  --oauth-issuer http://localhost:9100/realms/dev \
  --root-ca-path ./root-ca.pem \
  --root-ca-key-path ./root-ca-key.pem
```

### Run the Webhook Proxy
```bash
export RUST_LOG=info,rocket=warn,reqwest=warn

./target/release/wazuh-cert-oauth2-webhook \
  --server-base-url http://localhost:8000 \
  --oauth-issuer http://localhost:9100/realms/dev \
  --oauth-client-id test-client-secret \
  --oauth-client-secret some-secret
```

### Run the Client CLI
```bash
export RUST_LOG=info,reqwest=warn

./target/release/wazuh-cert-oauth2-client oauth2 \
  --issuer http://localhost:9100/realms/dev \
  --client-id test-client \
  --endpoint http://localhost:8000/api/register-agent
```

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
| `--oauth-client-secret`| `OAUTH_CLIENT_SECRET`| (Required) | Client Secret for the Server. |
| `--github-token` | `GITHUB_TOKEN` | (Optional) | GitHub PAT for issue creation. |
| `--github-repo-owner`| `GITHUB_REPO_OWNER` | (Optional) | Owner of the repo for tickets. |
| `--github-repo-name` | `GITHUB_REPO_NAME` | (Optional) | Name of the repo for tickets. |

### Client Flags
| Flag | Env Variable | Default | Purpose |
| :--- | :--- | :--- | :--- |
| `--issuer` | `ISSUER` | Keycloak URL | OIDC issuer for agent auth. |
| `--client-id` | `CLIENT_ID` | `adorsys-machine-client` | Agent's OAuth2 client ID. |
| `--endpoint` | `ENDPOINT` | registration URL | Server endpoint for CSR submission. |
| `--cert-path` | `CERT_PATH` | (Platform specific) | Destination for the signed cert. |

---

## Troubleshooting & Debugging

This section covers common issues encountered when setting up or running the project.

### 🌐 Connectivity Issues

#### "error sending request for url" (Client)
> [!IMPORTANT]
> **Symptom:** The client fails with an error similar to:  
> `An error occurred during execution: HTTP error: error sending request for url (http://localhost:9100/realms/dev/.well-known/openid-configuration)`

**Cause:** The OIDC provider (Keycloak) is not reachable from the client's network.  
**Solution:** 
- If using `docker compose`, verify you can access `http://localhost:9100/realms/dev/.well-known/openid-configuration` in your host browser.
- Ensure the `ISSUER` URL in your client configuration matches the reachable address of your OIDC provider.

#### 401 Unauthorized or "Could not get JWKS" (Server)
> [!WARNING]
> **Symptom:** Server logs show `Could not get JWKS HTTP error: error sending request for url (...)` or the client receives a 401 Unauthorized error.

**Cause:** The Certificate Server cannot reach the OIDC issuer to validate tokens.  
**Solution:** When running in Docker, services must use **internal service names**. Ensure `OAUTH_ISSUER` in `compose.yaml` uses `http://keycloak:9100/...` instead of `localhost`.

---

### 🔑 Permissions & Security

#### "Permission Denied (os error 13)"
> [!CAUTION]
> **Symptom:** `CSR signing failed: I/O error: Permission denied (os error 13)` appears in logs.

**Cause:** The container user (UID 1001) cannot read the host-mounted Root CA files.  
**Solution:** 
- **Linux/macOS:** The `compose.yaml` is already configured to map your host user via `UID` and `GID` environment variables. Ensure these are set in your shell or `.env` file.
- **Windows (Docker Desktop):** Docker Desktop usually handles permission mapping automatically. However, if you experience this error, ensure the files are not "Blocked" by Windows Security and that your Docker Desktop has permission to access the repository folder.

> [!TIP]
> On Linux, if your shell doesn't automatically export UID/GID, you can run:
> ```bash
> UID=$(id -u) GID=$(id -g) docker compose up -d
> ```

#### "Executable file not found" (docker exec)
> [!NOTE]
> **Symptom:** `OCI runtime exec failed: ... exec: "ls": executable file not found in $PATH`

**Cause:** This project uses **Distroless** images for enhanced security. They do not contain shells or standard utilities like `ls` or `sh`.  
**Solution:** 
1. Use `docker compose logs -f <service>` for debugging.
2. To inspect files, use the provided `ubuntu` sidecar service:
   ```bash
   docker compose exec ubuntu ls -R /data
   ```

---

### ⚙️ Infrastructure & Setup

#### keycloak-config "Restarting"
**Symptom:** The `keycloak-config` container shows a status of `Restarting` for the first minute.  
**Cause:** It attempts to configure Keycloak before Keycloak is fully booted.  
**Solution:** No action needed. It will eventually succeed once Keycloak is ready.

#### Version/Help Flags not working
**Note:** If you are using an older version of the binaries, help and version flags might not exit correctly. Ensure you have rebuilt the binaries after recent updates.
