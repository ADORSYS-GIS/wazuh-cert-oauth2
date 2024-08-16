#!/usr/bin/env bats

if [ "$(uname -o)" = "GNU/Linux" ] && command -v groupadd >/dev/null 2>&1; then
    apt-get install -y curl
elif [ "$(which apk)" = "/sbin/apk" ]; then
    apk add --no-cache curl
else
    log ERROR "Unsupported OS for creating user."
    exit 1
fi

chmod +x /app/scripts/install.sh

# Test if the script runs without errors
@test "script runs without errors" {
  run /app/scripts/install.sh
  [ "$status" -eq 0 ]
}

# Test if the binary is downloaded
@test "binary is downloaded" {
  /app/scripts/install.sh
  [ -f "$HOME/.local/bin/wazuh-cert-oauth2-client" ]
}

# Test if the shell configuration is updated
@test "shell configuration updated" {
  /app/scripts/install.sh
  grep -q -i 'export' "$HOME/.bashrc"
  grep -q -i 'export RUST_LOG=info' "$HOME/.bashrc"
}

# Test if the Wazuh agent certificates are configured
@test "Wazuh agent certificates configured" {
  /app/scripts/install.sh
  if [ -f "$OSSEC_CONF_PATH" ]; then
    grep -q '<agent_certificate_path>etc/sslagent.cert</agent_certificate_path>' "$OSSEC_CONF_PATH"
    grep -q '<agent_key_path>etc/sslagent.key</agent_key_path>' "$OSSEC_CONF_PATH"
  fi
}
