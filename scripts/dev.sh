#!/usr/bin/env bash
set -eEuo pipefail

# Setup scratch
SCRATCH="$(pwd)/tmp"
mkdir -p "${SCRATCH}/plugins"

# Build plugin
go build -o "${SCRATCH}/plugins/vault-auth-slack"

# Run vault
vault server \
  -dev \
  -dev-plugin-init \
  -dev-plugin-dir "${SCRATCH}/plugins" \
  -dev-root-token-id "root" \
  -log-level "debug" \
  &
sleep 2
VAULT_PID=$!

# Cleanup
function cleanup {
  echo ""
  echo "==> Cleaning up"
  kill -INT "${VAULT_PID}"
  rm -rf "${SCRATCH}"
}
trap cleanup EXIT

# Login
vault login root

vault write sys/policy/user policy=-<<EOF
path "secret/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
EOF
vault write sys/policy/group policy=-<<EOF
path "secret/*" {
  capabilities = ["read"]
}
EOF
vault write sys/policy/usergroup policy=-<<EOF
path "*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
EOF

# Enable plugin
vault plugin list
vault auth enable -path=slack -plugin-name=vault-auth-slack plugin

# Configure
vault write auth/slack/config \
  access_token="${SLACK_ACCESS_TOKEN}" \
  teams="${SLACK_TEAMS}"

# Display config
vault read auth/slack/config

# Add policies
vault write auth/slack/map/users/sethvargo policy=user
vault write auth/slack/map/groups/events policy=group
vault write auth/slack/map/usergroups/vault policy=usergroup

# Wait
wait $!
