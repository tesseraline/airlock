#!/bin/sh
# Prepares RUN (outside git): per-service certificate folders holding only what each service needs, owned by the
# user that service runs as; the two example secrets; the log folder for the gateway.
#   stage.sh RUN   (run as root; running containers keep the old folders, so restart them after a re-run)
set -eu
run="${1:?usage: stage.sh RUN}"
here="$(cd "$(dirname "$0")" && pwd)"
[ -n "$run" ] && [ "$run" != "/" ] || { echo "refusing RUN=$run"; exit 1; }
"$here/make-certs.sh" "$run/pki" 30 >/dev/null
umask 077
mkdir -p "$run/secrets" "$run/logs" "$run/certs"
# example secrets: random, and without a trailing newline (the gateway refuses a secret with a line break)
for f in demo-api-token model-key; do
  [ -f "$run/secrets/$f" ] || head -c 24 /dev/urandom | base64 | tr -d '/+=\n' > "$run/secrets/$f"
  v="$(tr -d '\r\n' < "$run/secrets/$f")"; printf '%s' "$v" > "$run/secrets/$f"
done

# service uid files...
stage() {
  svc="$1"; uid="$2"; shift 2
  rm -rf "$run/certs/$svc"; mkdir -p "$run/certs/$svc"
  for f in "$@"; do cp "$run/pki/$f" "$run/certs/$svc/"; done
  chown -R "$uid" "$run/certs/$svc"; chmod 0500 "$run/certs/$svc"; chmod 0400 "$run/certs/$svc"/*
}
stage gateway    10001 ca.pem gateway.pem gateway-key.pem
stage opa-tools  1000  ca.pem opa-tools.pem opa-tools-key.pem
stage egress     101   ca.pem egress.pem egress-key.pem upstream-ca.pem
stage vault      100   ca.pem vault.pem vault-key.pem
stage demo-api   10002 demo-api.pem demo-api-key.pem
mkdir -p "$run/secrets-vault" "$run/secrets-demo"
for d in secrets-vault secrets-demo; do cp "$run/secrets/demo-api-token" "$run/secrets/model-key" "$run/$d/"; done
chown -R 100 "$run/secrets-vault"; chown -R 10002 "$run/secrets-demo"
chmod 0500 "$run/secrets-vault" "$run/secrets-demo"; chmod 0400 "$run/secrets-vault"/* "$run/secrets-demo"/*
chown 10001 "$run/logs"; chmod 0750 "$run/logs"
echo "staged in $run"
