# Wazuh OAuth2 Proxy Server

[![Build Docker image](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/actions/workflows/build.yml/badge.svg)](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/actions/workflows/build.yml)
[![Helm Publish](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/actions/workflows/helm-publish.yml/badge.svg)](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/actions/workflows/helm-publish.yml)
[![Release Client](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/actions/workflows/release.yml/badge.svg)](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/actions/workflows/release.yml)

The Wazuh OAuth2 Proxy Server integrates Wazuh with an OAuth2 authentication system (e.g., Keycloak) to enhance security for Wazuh agents. This project allows users to authenticate through OAuth2 and acquire a signed certificate from the server. This certificate is used to authenticate subsequent requests to the Wazuh server, bolstering security with certificate-based access control.

## Features
- **OAuth2 Authentication:** Uses OAuth2 (via Keycloak) for secure user authentication.

- **Certificate-Based Access:** Issues certificates signed by the server CA to authenticated users for secure request validation.

- **Token Verification:** Validates tokens before issuing certificates, ensuring only authorized users receive access.

- **Scalable Deployment:** Easily deployable via Docker and Helm for integration into Kubernetes environments.

## Installation
To install this, you need to have a Keycloak server running. You can use the
docker-compose file in the `keycloak` folder to start a Keycloak server.

```bash
docker-compose -f keycloak/docker-compose.yml up -d
```

After that, you need to create a realm and a client in Keycloak. You can use
the `keycloak/realm.json` file to import the realm configuration.

```bash
curl -X POST -H "Content-Type: application/json" -d @keycloak/realm.json http://localhost:8080/auth/realms
```

## Agent companion installation
To install the agent companion, you need to run the script that will download
it and install it for you:

```bash
curl -sL https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-cert-oauth2/main/scripts/install.sh | bash
```

## Server companion installation
The server companion is installed through a helm chart

## Usage
```bash
wazuh-cert-oauth2-client -h
```
## Integration with Wazuh
This project is configured to integrate seamlessly with Wazuh. Once the proxy server is running, Wazuh agents can authenticate with Keycloak, acquire a signed certificate, and use it to send secure, authenticated requests to the Wazuh server.

