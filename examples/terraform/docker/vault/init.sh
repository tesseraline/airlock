#!/bin/sh
# Runs inside the Vault container at every start, against its local dev listener: cert login for the gateway, a
# read-only policy for its secrets, and the two example secrets. Dev mode keeps everything in memory.
set -eu
export VAULT_ADDR=http://127.0.0.1:8201
until vault status >/dev/null 2>&1; do sleep 1; done
vault auth list | grep -q '^cert/' || vault auth enable cert
vault policy write airlock-gateway - <<'P'
path "secret/data/airlock/*" { capabilities = ["read"] }
P
vault write auth/cert/certs/airlock-gateway certificate=@/certs/ca.pem \
  allowed_uri_sans="spiffe://airlock/gateway" token_policies=airlock-gateway token_ttl=15m >/dev/null
vault kv put secret/airlock/demo-api value=@/secrets/demo-api-token >/dev/null      # from the file, not the command line
vault kv put secret/airlock/model-demo value=@/secrets/model-key >/dev/null
echo "vault ready: cert login for spiffe://airlock/gateway, secrets airlock/demo-api and airlock/model-demo"
