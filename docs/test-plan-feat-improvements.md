# Test Plan

## Overview

| Field | Details |
| :--- | :--- |
| Repo Name/Version | wazuh-cert-oauth2 / feat/improvements (0.4.3-rc.3) |
| Purpose | Validate new features: automated OAuth2 callback flow, single active cert enforcement, webhook persistent spooling, and Wazuh agent eviction pipeline |
| Target Systems | Linux, macOS, and Windows |
| Maintainer | @Desmond Tardzenyuy |

---

## Test Environment

| Item | Details |
| :--- | :--- |
| OS Distribution | Linux (Ubuntu 22, Ubuntu 24), macOS (Intel, ARM), and Windows |
| Network Access | Online |
| Pre-Installed SW | Wazuh Agent |

### Required Commands

**Install Wazuh Agent:**
```sh
curl -SL --progress-bar https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-agent/refs/heads/main/scripts/install.sh | sudo bash
```

**Install wazuh-cert-oauth2:**

Linux / macOS:
```sh
curl -SL --progress-bar https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-cert-oauth2/refs/heads/feat/improvements/scripts/install.sh | sudo bash
```

Windows (PowerShell as Administrator):
```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-cert-oauth2/refs/heads/feat/improvements/scripts/install.ps1" -OutFile "$env:TEMP\install.ps1"; & "$env:TEMP\install.ps1"
```

**Uninstall wazuh-cert-oauth2:**

Linux / macOS:
```sh
curl -SL --progress-bar https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-cert-oauth2/refs/heads/feat/improvements/scripts/uninstall.sh | sudo bash
```

---

## Test Cases

| Test ID | Description | Pre-Conditions | Steps | Expected Result | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| T01 | Fresh install on clean OS | Wazuh agent installed | Run install.sh | Script installs successfully without errors | ✅/❌ |
| T02 | Re-install on already installed system | Previous install present | Run install.sh again | Script handles existing install gracefully | ✅/❌ |
| T03 | Uninstall from machine | wazuh-cert-oauth2 installed | Run uninstall.sh | Script uninstalls cleanly without errors | ✅/❌ |
| T04 | Re-uninstall from machine | wazuh-cert-oauth2 already uninstalled | Run uninstall.sh again | Script warns appropriately, exits cleanly | ✅/❌ |
| T05 | OAuth2 enrollment — automated callback flow | wazuh-cert-oauth2 and Wazuh agent installed | Run `wazuh-cert-oauth2-client --oauth2`; complete login in browser | Client receives token via local callback server without manual code paste; agent enrolled successfully | ✅/❌ |
| T06 | Single active cert enforcement — re-enrollment rejected without admin role | Existing active cert for subject; user does NOT have `wazuh_admin` role in Keycloak | Re-run enrollment for same user without `--overwrite` flag | Server rejects enrollment with an error; no new cert issued; existing cert untouched | ✅/❌ |
| T07 | Single active cert enforcement — re-enrollment allowed with admin role | Existing active cert for subject; user HAS `wazuh_admin` role in Keycloak | Re-run enrollment for same user without `--overwrite` flag | Previous certificate is auto-revoked; new cert issued; CRL updated | ✅/❌ |
| T08 | Single active cert enforcement — overwrite flag bypasses role check | Existing active cert for subject | Re-run enrollment with `--overwrite` flag (any user) | Previous cert revoked, new cert issued, agent eviction triggered | ✅/❌ |
| T09 | Webhook revocation — server reachable | Keycloak and server running | Disable or delete user in Keycloak | Webhook forwards revocation to server immediately; cert marked revoked; CRL rebuilt | ✅/❌ |
| T10 | Webhook revocation — server down (spool) | Server unreachable | Disable user in Keycloak while server is stopped | Revocation request spooled to disk; retried automatically once server recovers | ✅/❌ |
| T11 | Webhook GitHub ticket — user registration | GitHub token configured | Register new user in Keycloak | GitHub issue created in configured repo | ✅/❌ |
| T12 | Webhook GitHub ticket — GitHub unreachable (spool) | GitHub API unreachable | Register new user in Keycloak while GitHub is blocked | Ticket request spooled to disk; retried automatically once GitHub is reachable | ✅/❌ |
| T13 | Wazuh agent eviction — standard revocation | Active Wazuh agent registered for subject | Trigger revocation with a non-auto-rotate reason | Active response sent to agent; grace period observed; agent deleted from Wazuh manager | ✅/❌ |
| T14 | Wazuh agent eviction — auto-rotate reason | Active Wazuh agent registered for subject | Trigger revocation with `auto-rotate` reason | Agent deleted directly without active response or grace period | ✅/❌ |
| T15 | Wazuh agent eviction — eviction spooling on failure | Wazuh manager unreachable | Trigger revocation while Wazuh manager is down | Eviction request spooled to disk; retried automatically once manager recovers | ✅/❌ |
| T16 | Wazuh agent eviction — spool timeout (TTL) | Wazuh agent offline; AR command spooled | Wait until `WAZUH_AR_SPOOL_TTL_SECONDS` expires | Agent is forced to be deleted from Wazuh manager despite offline status | ✅/❌ |

---

## Cross-OS Validation Matrix

| OS / Test Case | T01 | T02 | T03 | T04 | T05 | T06 | T07 | T08 | T09 | T10 | T11 | T12 | T13 | T14 | T15 | T16 | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| Ubuntu 22 | | | | | | | | | | | | | | | | | |
| Ubuntu 24 | | | | | | | | | | | | | | | | | |
| macOS Intel | | | | | | | | | | | | | | | | | |
| macOS ARM | | | | | | | | | | | | | | | | | |
| Windows | | | | | | | | | | | | | | | | | |

---

## Issues & Fixes

| Issue ID | Description | Severity | Fix / Workaround | Status |
| :--- | :--- | :--- | :--- | :--- |
| I01 | | | | |
| I02 | | | | |

---

## Final Summary

| Field | Details |
| :--- | :--- |
| Overall Status | Pass / Fail |
| Validated By | |
| Date | |
| Next Steps | |
