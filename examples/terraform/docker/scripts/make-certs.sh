#!/bin/sh
# Creates a local CA and short-lived certificates for the example stack. Private keys stay in OUTDIR (git ignores
# it). Re-run to rotate; the gateway loads new certificates on SIGHUP.
#   make-certs.sh OUTDIR [DAYS]
set -eu
out="${1:?usage: make-certs.sh OUTDIR [DAYS]}"
days="${2:-30}"
mkdir -p "$out"
cd "$out"
umask 077

if [ ! -f ca-key.pem ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca-key.pem -out ca.pem \
    -days 365 -subj "/CN=airlock example CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
fi

# leaf NAME SAN EKU
leaf() {
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$1-key.pem" -out "$1.csr" \
    -subj "/CN=$1" 2>/dev/null
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=%s\nsubjectAltName=%s\n' \
    "$3" "$2" > "$1.ext"
  openssl x509 -req -in "$1.csr" -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out "$1.pem" -days "$days" \
    -extfile "$1.ext" 2>/dev/null
  rm -f "$1.csr" "$1.ext"
}

leaf gateway   "DNS:gateway,DNS:localhost,IP:127.0.0.1,URI:spiffe://airlock/gateway" "serverAuth,clientAuth"
leaf agent     "URI:spiffe://airlock/agent/researcher" "clientAuth"
leaf opa-tools "DNS:opa-tools,DNS:localhost,IP:127.0.0.1" "serverAuth"
leaf vault     "DNS:vault,DNS:localhost,IP:127.0.0.1" "serverAuth"
leaf egress    "DNS:egress,DNS:localhost,IP:127.0.0.1" "serverAuth"
leaf demo-api  "DNS:demo-api,DNS:localhost,IP:127.0.0.1" "serverAuth"

# what the egress proxy trusts upstream: the public CAs plus ours (for demo-api)
cat /etc/ssl/certs/ca-certificates.crt ca.pem > upstream-ca.pem 2>/dev/null || cp ca.pem upstream-ca.pem
chmod 0600 ./*-key.pem
for f in ./*.pem; do case "$f" in *-key.pem) ;; *) chmod 0644 "$f" ;; esac; done
echo "certificates in $out, valid $days days"
