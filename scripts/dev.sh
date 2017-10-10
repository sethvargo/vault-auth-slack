#!/usr/bin/env bash
set -e

#
# Helper script for local development. Automatically builds and registers the
# plugin. Requires `vault` is installed and available on $PATH.
#

# Get the right dir
DIR="$(cd "$(dirname "$(readlink "$0")")" && pwd)"

echo "==> Starting dev"

echo "--> Scratch dir"
echo "    Creating"
SCRATCH="$DIR/tmp"
mkdir -p "$SCRATCH/plugins"

echo "--> Vault server"
echo "    Writing config"
tee "$SCRATCH/vault.hcl" > /dev/null <<EOF
plugin_directory = "$SCRATCH/plugins"
EOF

echo "    Starting"
vault server \
  -dev \
  -dev-root-token-id="root" \
  -log-level="debug" \
  -config="$SCRATCH/vault.hcl" \
  &
sleep 2
VAULT_PID=$!

function cleanup {
  echo ""
  echo "==> Cleaning up"
  kill -INT "$VAULT_PID"
  rm -rf "$SCRATCH"
}
trap cleanup EXIT

echo "    Authing"
vault auth root &>/dev/null

echo "--> Creating policies"
vault write sys/policy/user rules=-<<EOF
path "secret/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
EOF
vault write sys/policy/group rules=-<<EOF
path "secret/*" {
  capabilities = ["read"]
}
EOF
vault write sys/policy/usergroup rules=-<<EOF
path "*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
EOF

echo "--> Building"
go build -o "$SCRATCH/plugins/vault-auth-slack"
SHASUM=$(shasum -a 256 "$SCRATCH/plugins/vault-auth-slack" | cut -d " " -f1)

echo "    Registering plugin"
vault write sys/plugins/catalog/slack-auth-plugin \
  sha_256="$SHASUM" \
  command="vault-auth-slack"

echo "    Mouting plugin"
vault auth-enable -path=slack -plugin-name=slack-auth-plugin plugin

echo "--> Configuring"
vault write auth/slack/config \
  access_token="$SLACK_ACCESS_TOKEN" \
  teams="$SLACK_TEAMS"

echo "    Reading out"
vault read auth/slack/config

echo "--> Mapping policies"
vault write auth/slack/map/users/sethvargo policy=user
vault write auth/slack/map/groups/events policy=group
vault write auth/slack/map/usergroups/vault policy=usergroup

echo "==> Ready!"
wait $!
