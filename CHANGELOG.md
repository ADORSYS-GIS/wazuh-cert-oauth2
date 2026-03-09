## [wazuh-cert-webhook-0.4.2] - 2026-02-23

### 🚀 Features

- *(windows installer)* Add installation validation function to install.ps1

### ⚙️ Miscellaneous Tasks

- Update default WOPS version to 0.4.0 in install.ps1
## [0.4.1] - 2026-02-20

### 🐛 Bug Fixes

- *(cli)* Handle browser launch correctly under sudo
- *(cli)* Launch browser as desktop user with proper GUI env
- *(cli)* Handle browser launch correctly under sudo (#130)

### ⚙️ Miscellaneous Tasks

- Upgrade WOPS_VERSION -> 0.4.1
- Upgrade app version -> 0.4.2
## [0.4.0] - 2025-11-27

### 🐛 Bug Fixes

- *(windows client)* Update open_in_browser function for Windows to use rundll32 to avoid parsing issues

### ⚙️ Miscellaneous Tasks

- Upgrade WOPS_VERSION -> 0.4.0
## [wazuh-cert-webhook-0.3.0] - 2025-11-16

### ⚙️ Miscellaneous Tasks

- Version upgrade => 0.3.0
## [0.2.23-rc.5] - 2025-11-16

### ⚙️ Miscellaneous Tasks

- Version upgrade
## [0.2.23-rc.4] - 2025-11-16

### 🐛 Bug Fixes

- Cert gen
## [0.2.23-rc.3] - 2025-11-15

### ⚙️ Miscellaneous Tasks

- Dockerfile uograded to use musl
- Dockerfile multi-arch support
- Port config
- Version upgrade
- Format
- Format
## [0.2.23-rc.2] - 2025-11-15

### ⚙️ Miscellaneous Tasks

- Openssl vendored
- Openssl vendored
- Openssl vendored
- Openssl vendored
- Openssl vendored
- Openssl vendored
- Openssl vendored
- Openssl vendored
- Openssl vendored
- Openssl vendored
- Openssl vendored
- Openssl vendored
- Openssl vendored
- Openssl vendored
- Openssl vendored
- Openssl vendored
- Version upgrade
## [0.2.23-rc.1] - 2025-11-13

### ⚙️ Miscellaneous Tasks

- Version upgrade
## [wazuh-cert-webhook-0.2.27] - 2025-11-13

### ⚙️ Miscellaneous Tasks

- Version upgrade
## [wazuh-cert-webhook-0.2.26] - 2025-11-13

### ⚙️ Miscellaneous Tasks

- Version upgrade
## [wazuh-cert-server-0.2.25] - 2025-11-13

### ⚙️ Miscellaneous Tasks

- Version upgrade
## [wazuh-cert-webhook-0.2.25] - 2025-11-13

### ⚙️ Miscellaneous Tasks

- Version upgrade
## [wazuh-cert-webhook-0.2.24] - 2025-11-13

### ⚙️ Miscellaneous Tasks

- Version upgrade
## [wazuh-cert-server-0.2.24] - 2025-11-13

### ⚙️ Miscellaneous Tasks

- Version upgrade
## [wazuh-cert-webhook-0.2.23] - 2025-11-13

### ⚙️ Miscellaneous Tasks

- Version upgrade
## [wazuh-cert-webhook-0.2.22] - 2025-11-13

### ⚙️ Miscellaneous Tasks

- Version upgrade
## [wazuh-cert-server-0.2.22] - 2025-11-13

### 🚀 Features

- Jwt prefered username (#81)
## [0.2.22-rc.1] - 2025-10-07

### 🐛 Bug Fixes

- Remove icacls executable does not need to be assigned exe permissions
- Add executable permissions to cert-oauth2.exe for windows of all languages
## [wazuh-cert-webhook-0.2.21] - 2025-09-08

### ⚙️ Miscellaneous Tasks

- *(helm)* Csv s3 backup
- *(helm)* Version upgrade
- *(helm)* Version upgrade
## [0.2.20-rc.3] - 2025-09-08

### 🐛 Bug Fixes

- *(ci)* Build.yml removed manual sbom

### ⚙️ Miscellaneous Tasks

- Version upgrade (#33)
- *(ci)* Removed optional sbom from build ci (#34)
## [wazuh-cert-webhook-0.2.20] - 2025-09-07

### 🚀 Features

- CRL helm charts and Upgrade Code structure (#23)
## [0.2.19] - 2025-06-04

### ⚙️ Miscellaneous Tasks

- Release version 0.2.18
## [0.2.18] - 2025-05-26

### 🐛 Bug Fixes

- *(service)* Add restart_agent and stop_agent services to fix set_name issue on windows
- Update wazuh-cert-oauth2-client version to 0.2.18 and remove unused restart_agent import
- Update wazuh-cert-oauth2-client version to 0.2.18 and remove unused restart_agent import
- *(service)* Update restart_agent and stop_agent to use powershell commands for Windows
- Add success message after agent enrollment completion
- Update default WOPS version to 0.2.18 in install scripts
- Add logging for agent name update confirmation
## [0.2.17] - 2025-02-19

### 🐛 Bug Fixes

- Remove update agent_name functionality
- Add agentName as placeholder in enrollment block
- Set omit xml declaration to true
- Change Logging Method to match other scripts
- Bin url and removed unecessary variables
- Bin url

### ⚙️ Miscellaneous Tasks

- Add placeholder agent name
## [0.2.16] - 2025-02-11

### ⚙️ Miscellaneous Tasks

- Version upgrade -> 0.2.16
- Better CI
## [0.2.15] - 2025-02-11

### 🚀 Features

- Optimized docker file (#8)

### 🐛 Bug Fixes

- Enrollment block is not added in correct position

### ⚙️ Miscellaneous Tasks

- Add enrollment block after server block
- Version upgrade
## [0.2.13] - 2025-01-17

### 🐛 Bug Fixes

- *(chore)* Use gsed to rename agent in macos

### 💼 Other

- Add debugging line in set_name function

### 🧪 Testing

- Update env variables

### ⚙️ Miscellaneous Tasks

- WOPS_VERSION -> 0.2.13
- Client-version -> 0.2.13
## [0.2.12] - 2025-01-17

### 🚀 Features

- *(chore)* Add uninstall script
- *(chore)* Add installation validation steps
- Update sed command to work for windows os
- Add functionality to sed edit agent_name for windows

### 🐛 Bug Fixes

- *(chore)* Add maybe_sudo infront of file checks
- *(chore)* Add maybe_sudo infront of file checks
- *(chore)* Add maybe_sudo where needed and add sed_alternative in uninstall script
- *(chore)* Add sed_alternative in uninstall script
- *(chore)* Remove maybe_sudo where needed
- *(chore)* Remove maybe_sudo where needed
- *(chore)* Error handling if binary already exists. File is replaced by new installation
- *(enrollment)* Simplify and improve certificate configuration
- Update windows path to ossec.conf to not be in etc folder
- Syntax error line 32 expected ; but found path_buf
- Remove whitespace between cfg! and ( on line 27
- Remove semi-colon from line 30 and line 28 & some syntax formatting
- Agent_name is added in 1 line rather than 2 lines
- Using powershell as command instead of sed

### 💼 Other

- *(chore)* Added colours to message printing function

### ⚙️ Miscellaneous Tasks

- Update default WOPS_VERSION to 0.2.11
- DEFAULT_WOPS_VERSION -> 0.2.12
- Correct ossec config path
## [0.2.11] - 2024-12-17

### 🚀 Features

- Version upgrade
## [0.2.10] - 2024-12-17

### 🚀 Features

- Fix sed -> sed_alternative

### 🐛 Bug Fixes

- Use different sed command depending on OS
## [0.2.9] - 2024-12-03

### 🚀 Features

- Fix name with special char
## [0.2.8] - 2024-10-22

### 🚀 Features

- Windows installation path
- Windows path for certs

### ⚙️ Miscellaneous Tasks

- Update ossec conf path to be multiplatform
## [0.2.6] - 2024-10-11

### 🐛 Bug Fixes

- Linux deps
- Linux deps
- Linux deps

### 📚 Documentation

- Added more descriptive comments

### ⚙️ Miscellaneous Tasks

- Configure agent certificates in ossec.conf
- Configure agent certificates in ossec.conf
- Configure agent certificates in ossec.conf
- Update WOPS version to 0.2.5 and handle download fallback
- Efs config; v0.2.5
- Certificates config
- Certificates config
- Updated set_name to use smaller names; version upgrade till 0.2.6;
## [0.2.4] - 2024-10-04

### ⚙️ Miscellaneous Tasks

- Efs config; v0.2.4
- Efs config; v0.2.4
## [0.2.3] - 2024-10-04

### ⚙️ Miscellaneous Tasks

- Removed unused tests
- Agent_name added; version upgrade to 0.2.3
## [0.2.2] - 2024-10-01

### 🐛 Bug Fixes

- Permission in script
- Make source shell universal
- Solve sed command call

### 💼 Other

- Updated version for consistency

### 🚜 Refactor

- Improve script

### ⚙️ Miscellaneous Tasks

- Config
- Config
- Improve certs configuration
- Used sed_alternative
- Default values for MacOS; version upgrade to 0.2.2
## [0.2.1] - 2024-09-12

### ⚙️ Miscellaneous Tasks

- Updated windows script
## [0.2.0] - 2024-09-12

### 🚀 Features

- Added ossec.conf update
- Tests written using bats

### 🐛 Bug Fixes

- Ci docker non-interactive

### ⚙️ Miscellaneous Tasks

- Typo changes
- More colors to the bash script
- Updated keycloak issuer to wazuh's keycloak
## [0.1.7] - 2024-08-15

### 🐛 Bug Fixes

- Test-script scripts
- Added buildx
- Script date arg

### 🧪 Testing

- Fix script docker test cases
- Fix script docker test cases

### ⚙️ Miscellaneous Tasks

- Added curl to images
## [0.1.7] - 2024-08-15

### ⚙️ Miscellaneous Tasks

- V0.1.7
## [0.1.6] - 2024-08-15

### ⚙️ Miscellaneous Tasks

- Helm chart ingress fix
- Helm chart ingress fix
- Helm chart sa fix
- Helm chart image fix
- Rocket config address
- Rocket re-config address
- Scripts updated for non-interactive bash
- Updated README.md
- Structure changes
- V0.1.6
## [0.1.5] - 2024-08-13

### 🐛 Bug Fixes

- Openssl

### ⚙️ Miscellaneous Tasks

- Helm charts version update
- Update script versions
## [0.1.4] - 2024-08-13

### ⚙️ Miscellaneous Tasks

- First ready script, tested
- Helm charts
## [0.1.3] - 2024-08-13

### ⚙️ Miscellaneous Tasks

- First ready script, tested
## [0.1.2] - 2024-08-13

### ⚙️ Miscellaneous Tasks

- First ready script, tested
## [0.1.1] - 2024-08-13

### 💼 Other

- Changed title of workflow

### ⚙️ Miscellaneous Tasks

- Initial commit
- Setup github action
- Setup helm chart
- Readme
- Project structure
- Client
- First ready version
- First ready script
