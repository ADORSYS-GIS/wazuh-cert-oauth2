# Project Architecture

This document describes the high-level architecture of the `wazuh-cert-oauth2` project and how its components interact.

## Components Overview

1.  **Wazuh Agent CLI (`wazuh-cert-oauth2-client`)**: A CLI tool run on the Wazuh agent host. It handles user authentication via OIDC, CSR generation, and submission to the backend.
2.  **Certificate Server (`wazuh-cert-oauth2-server`)**: The central backend that validates OIDC tokens, signs CSRs using a Root CA, and manages the Certificate Revocation List (CRL).
3.  **Webhook Proxy (`wazuh-cert-oauth2-webhook`)**: A specialized service that listens for events from the Identity Provider (e.g., Keycloak) and triggers certificate revocations in the backend.
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

    AgentClient->>AgentClient: Construct Authorization URL
    AgentClient->>User: Display auth URL in terminal
    User->>Keycloak: Open browser (if not automatically opened by client), login and authorize
    Keycloak-->>User: Show authorization code (manual copy)
    User->>AgentClient: Paste authorization code

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
        Webhook->>Webhook: Queue Revocation Request
        Webhook->>Webhook: Retry in background
    end
```

#### Webhook Details:
- **Resiliency**: The Webhook Proxy includes a persistent spooling mechanism. If the Certificate Server is unavailable, revocation requests are queued and retried automatically.
- **Filtering**: Not all Keycloak events trigger a revocation. The proxy is configured to listen specifically for events that imply a user should no longer have access (e.g., account deletion or disabling).

---

## Component Responsibilities

| Component | Responsibility |
| :--- | :--- |
| **Client** | CSR Generation, OIDC Auth, Local Config Management |
| **Server** | Token Validation, CSR Signing (CA), CRL Generation, Ledger Persistence |
| **Webhook** | Event Transformation, Reliable Revocation Forwarding |
| **Model** | Shared Data Structures & Error Types (used by all crates) |
