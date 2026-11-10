# R01: Enroll a new agent

**Symptom:** A new Wazuh agent needs a certificate to authenticate.

**Steps:**

  1. On the agent host, run the client CLI with the OIDC flow. The binary is
     installed by the installation scripts to `/var/ossec/bin/wazuh-cert-oauth2-client`
     (Linux), `/Library/Ossec/bin/wazuh-cert-oauth2-client` (macOS), or
     `C:\Program Files (x86)\ossec-agent\wazuh-cert-oauth2-client.exe` (Windows).

**User flow** (interactive authorization-code):
         
```
/var/ossec/bin/wazuh-cert-oauth2-client oauth2
```

**Service-account flow** (for servers / machine identities, client-credentials):
         
```
/var/ossec/bin/wazuh-cert-oauth2-client oauth2 \
--client-id <client-id> \
--client-secret <client-secret> \
--is-service-account
```

  2. Complete the authorization (user flow): The client prints an authorization URL and opens the browser if possible. For the service-account flow, the token is obtained via client-credentials, so no interactive step is needed.

  3. Confirm the signed certificate and private key are written to the platform default path.

  4. Verify the agent connects to the manager and appears in the Wazuh Manager agent list.

**Notes:** One certificate per agent / per human user / per server; do not share certificates across users or machines. Keycloak principals with the `wazuh_admin` role are exempt. The service-account flow is for machine/service-account identities and requires `--client-secret` and `--is-service-account`.
---
