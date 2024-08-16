# Wazuh OAuth2 Proxy Server

[![Build Docker image](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/actions/workflows/build.yml/badge.svg)](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/actions/workflows/build.yml)
[![Helm Publish](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/actions/workflows/helm-publish.yml/badge.svg)](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/actions/workflows/helm-publish.yml)
[![Release Client](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/actions/workflows/release.yml/badge.svg)](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/actions/workflows/release.yml)
[![Test install script](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/actions/workflows/test-script.yml/badge.svg)](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/actions/workflows/test-script.yml)

This project demonstrate by example how to authenticate with Keycloak and 
submit a certificate to the end use. The goal is for the user to send a 
signed request after he go one from the server to the wazuh server, using
the certificate that was signed by the server CA.

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
