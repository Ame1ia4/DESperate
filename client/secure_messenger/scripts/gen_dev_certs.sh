#!/usr/bin/env bash
# Generates a local dev CA and a server certificate signed by it.
# Output goes to certs/dev/ (gitignored — never commit private keys).
# Use certs/dev/ca.crt as the TrustStore CA bundle for local dev builds.
# Production uses a real CA (e.g. Let's Encrypt); this script is dev-only.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTDIR="$SCRIPT_DIR/../certs/dev"
mkdir -p "$OUTDIR"

# ── CA key and self-signed certificate (EC P-384, 10 years) ──────────────
openssl ecparam \
    -name secp384r1 \
    -genkey \
    -noout \
    -out "$OUTDIR/ca.key"

openssl req \
    -new -x509 \
    -key "$OUTDIR/ca.key" \
    -out "$OUTDIR/ca.crt" \
    -days 3650 \
    -subj "/CN=DESperate Dev CA/O=DESperate/C=NL" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash"

# ── Server key (EC P-256) and CSR ────────────────────────────────────────
openssl ecparam \
    -name prime256v1 \
    -genkey \
    -noout \
    -out "$OUTDIR/server.key"

openssl req \
    -new \
    -key "$OUTDIR/server.key" \
    -out "$OUTDIR/server.csr" \
    -subj "/CN=localhost/O=DESperate/C=NL"

# ── Sign server certificate with the CA (1 year, with SANs) ──────────────
openssl x509 \
    -req \
    -in "$OUTDIR/server.csr" \
    -CA "$OUTDIR/ca.crt" \
    -CAkey "$OUTDIR/ca.key" \
    -CAcreateserial \
    -out "$OUTDIR/server.crt" \
    -days 365 \
    -extfile <(cat <<'EOF'
[ext]
subjectAltName      = DNS:localhost, IP:127.0.0.1
keyUsage            = critical, digitalSignature
extendedKeyUsage    = serverAuth
basicConstraints    = CA:FALSE
subjectKeyIdentifier = hash
EOF
) \
    -extensions ext

rm -f "$OUTDIR/server.csr" "$OUTDIR/ca.srl"

# ── Verify the chain ─────────────────────────────────────────────────────
echo ""
echo "Chain verification:"
openssl verify -CAfile "$OUTDIR/ca.crt" "$OUTDIR/server.crt"

echo ""
echo "CA certificate fingerprint (SHA-256):"
openssl x509 -in "$OUTDIR/ca.crt" -noout -fingerprint -sha256

echo ""
echo "Server certificate fingerprint (SHA-256):"
openssl x509 -in "$OUTDIR/server.crt" -noout -fingerprint -sha256

echo ""
echo "Files written to $OUTDIR:"
echo "  ca.key     — CA private key  (NEVER commit or deploy)"
echo "  ca.crt     — CA certificate  (pass to TrustStore in dev builds)"
echo "  server.key — Server private key  (deploy to server only)"
echo "  server.crt — Server certificate  (deploy to server only)"

# ── Write a local .gitignore to block accidental commits ─────────────────
cat > "$OUTDIR/.gitignore" <<'EOF'
*
!.gitignore
EOF
