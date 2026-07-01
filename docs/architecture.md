# Project Architecture

This document describes the high-level architecture of the `wazuh-cert-oauth2` project and how its components interact.

## Components Overview

1.  **Wazuh Agent CLI (`wazuh-cert-oauth2-client`)**: A CLI tool run on the Wazuh agent host. It handles user authentication via OIDC, CSR generation, and submission to the backend.
2.  **Certificate Server (`wazuh-cert-oauth2-server`)**: The central backend that validates OIDC tokens, signs CSRs using a Root CA, and manages the Certificate Revocation List (CRL).
3.  **Webhook Proxy (`wazuh-cert-oauth2-webhook`)**: A specialized service that listens for events from the Identity Provider (e.g., Keycloak). It features persistent disk-backed spooling for reliable delivery of revocations, GitHub issue creation, and Wazuh agent evictions via the Wazuh Manager REST API.
4.  **Keycloak (IdP)**: The Identity Provider responsible for user authentication and triggering webhook events when user states change.

---

## Communication Flows

### 1. Agent Enrollment (Client-Server Flow)

The following diagram illustrates the process of an agent obtaining a signed certificate via the OAuth2 flow.

```mermaid
sequenceDiagram
    autonumber

    participant User as User
    participant AgentClient as Wazuh Agent CLI (wazuh-cert-oauth2-client)
    participant Keycloak as Keycloak (Auth Server)
    participant WazuhAPI as Wazuh OAuth2 Backend

    User->>AgentClient: Run client with `--oauth2` flag

    Note over AgentClient,Keycloak: Initialization Phase

    AgentClient->>Keycloak: Fetch Discovery Document (.well-known/openid-configuration)
    AgentClient->>Keycloak: Fetch JWKS (JSON Web Key Set)
    Keycloak-->>AgentClient: Returns JWKS JSON

    Note over User,AgentClient: Authorization Phase

    AgentClient->>AgentClient: Construct Authorization URL & start local HTTP callback server
    AgentClient->>User: Display auth URL in terminal (opens browser automatically if possible)
    User->>Keycloak: Login and authorize in browser
    Keycloak-->>AgentClient: Redirect to localhost callback with authorization code

    AgentClient->>Keycloak: Exchange code for access token (and optionally ID token)
    Keycloak-->>AgentClient: Token response (access_token[, id_token, refresh_token])

    Note over AgentClient: Validation Phase

    AgentClient->>AgentClient: Validate JWT with JWKS (signature + audience + expiry)

    Note over AgentClient,WazuhAPI: Registration Phase

    AgentClient->>WazuhAPI: POST /register-agent with Bearer access_token
    WazuhAPI->>Keycloak: Validate access_token with JWKS
    WazuhAPI-->>AgentClient: Return agent ID, public cert, and private key

    Note over AgentClient: Finalization Phase

    AgentClient->>AgentClient: Agent Configuration wrap up

    AgentClient-->>User: Success message
```

### 2. Automated Revocation (Webhook Flow)

The Webhook Proxy automates certificate revocation when a user's account is disabled or deleted in Keycloak.

```mermaid
sequenceDiagram
    autonumber

    participant Keycloak as Keycloak (IdP)
    participant Webhook as Webhook Proxy (wazuh-cert-oauth2-webhook)
    participant Server as Certificate Server (wazuh-cert-oauth2-server)

    Keycloak->>Webhook: POST /webhook (User Deleted/Disabled)
    Webhook->>Webhook: Filter & Extract Subject (userId)

    Webhook->>Server: POST /api/revoke (Subject: userId)
    
    alt Server Reachable
        Server-->>Webhook: 204 NoContent (Success)
        Server->>Server: Mark all certs for Subject as Revoked
        Server->>Server: Rebuild CRL
    else Server Down
        Server-->>Webhook: Error / Timeout
        Note over Webhook: Spool for reliable retry
        Webhook->>Webhook: Spool Revocation Request to Disk
        Webhook->>Webhook: Retry in background from Spool
    end
```

### 3. User Registration Tracking (GitHub Issue Flow)

When a new user registers or is created in Keycloak, the Webhook Proxy handles the event and creates an issue in GitHub for administrative tracking.

```mermaid
sequenceDiagram
    autonumber

    participant Keycloak as Keycloak (IdP)
    participant Webhook as Webhook Proxy (wazuh-cert-oauth2-webhook)
    participant GitHub as GitHub API

    Keycloak->>Webhook: POST /webhook (User Registered/Created)
    Webhook->>Webhook: Extract User Metadata

    Webhook->>GitHub: POST /repos/{owner}/{repo}/issues
    
    alt Success
        GitHub-->>Webhook: 201 Created
    else Network Error / 5xx
        Note over Webhook: Spool for reliable retry
        Webhook->>Webhook: Spool Ticket Request to Disk
        Webhook->>Webhook: Retry in background from Spool
    end
```

### 4. Agent Eviction Flow

When a certificate is revoked, the corresponding Wazuh agent must be removed from the manager. The eviction pipeline resolves the agent by name via the Wazuh Manager REST API and deletes it directly.

#### 4a. Keycloak-Triggered Eviction (User Delete/Update)

When Keycloak fires a user-delete or user-update event, the webhook revokes the certificate and then queues an eviction request.

```mermaid
sequenceDiagram
    autonumber

    participant Keycloak as Keycloak (IdP)
    participant Webhook as Webhook Proxy
    participant Server as Certificate Server
    participant Wazuh as Wazuh Manager API

    Keycloak->>Webhook: POST /webhook (User Deleted/Updated)
    Webhook->>Webhook: Extract subject (userId)
    Webhook->>Server: GET /api/ledger/subject/{subject} (fetch agent name)
    Server-->>Webhook: Ledger entries (with wazuh_agent_name)
    Webhook->>Server: POST /api/revoke (revoke certificate)
    Server-->>Webhook: 204 No Content
    Server->>Server: Mark cert revoked, rebuild CRL

    Note right of Webhook: Queue eviction for agent
    Webhook->>Webhook: Spool EvictRequest to disk

    Note right of Webhook: Spool Processor
    Webhook->>Wazuh: GET /agents?search={agent_name} (resolve agent)
    Wazuh-->>Webhook: Agent ID
    Note right of Webhook: Wait grace period (default 30s)
    Webhook->>Wazuh: DELETE /agents/{agent_id}
    Wazuh-->>Webhook: 200 OK

    alt Wazuh API Unreachable
        Webhook->>Webhook: Keep EvictRequest in spool, retry later
    end
```

#### 4b. Auto-Rotate Eviction (Server-Triggered)

When the Certificate Server detects a re-enrollment that overrides an active certificate, it notifies the Webhook Proxy to evict the old agent immediately — no grace period.

```mermaid
sequenceDiagram
    autonumber

    participant Agent as Wazuh Agent CLI
    participant Server as Certificate Server
    participant Webhook as Webhook Proxy
    participant Wazuh as Wazuh Manager API

    Agent->>Server: POST /api/register-agent (re-enrollment)
    Server->>Server: Detect active cert for same subject
    Server->>Server: Revoke old cert, rebuild CRL
    Server->>Webhook: POST /api/internal/evict (subject, agent_name, "auto-rotate")

    Webhook->>Wazuh: GET /agents?search={agent_name} (resolve agent)
    Wazuh-->>Webhook: Agent ID
    Note right of Webhook: Grace period skipped for auto-rotate
    Webhook->>Wazuh: DELETE /agents/{agent_id}
    Wazuh-->>Webhook: 200 OK

    alt Wazuh API Unreachable
        Webhook->>Webhook: Spool EvictRequest, retry later
    end
```

#### Eviction Details:
- **Direct API**: The eviction pipeline resolves agents by name via `GET /agents?search=` and deletes them via `DELETE /agents/{id}` using the Wazuh Manager REST API.
- **Grace Period**: For Keycloak-triggered revocations, the webhook waits `WAZUH_EVICTION_GRACE_SECONDS` (default 30s) before deleting the agent, giving it time to receive the updated CRL and disconnect gracefully. This delay is skipped for auto-rotate revocations.
- **Resiliency**: If the Wazuh API is unreachable, the EvictRequest is persisted to the spool directory and retried in the background with exponential backoff.
- **Double-Failure Safety**: If both the direct eviction call and the spool queue fail, the `/api/internal/evict` endpoint returns `500 Internal Server Error` so the caller (cert-server) knows the request was lost and can retry.
- **Filtering**: The proxy identifies revoke-eligible events (`USER-DELETE`/`USER-UPDATE`) and ticket-eligible events (`REGISTER`/`USER-CREATE`).
- **GitHub Integration**: For registration events, the proxy automatically creates a tracking issue in the configured GitHub repository.

---

## Component Responsibilities

| Component | Responsibility |
| :--- | :--- |
| **Client** | CSR Generation, OIDC Auth, Local Config Management |
| **Server** | Token Validation, CSR Signing (CA), CRL Generation, Ledger Persistence |
| **Webhook** | Event Transformation, Persistent Spooling, Wazuh Agent Eviction (via REST API) |
| **Model** | Shared Data Structures & Centralized Wazuh API Client |
