#!/usr/bin/env bash
# generate-certs.sh — Create a self-signed CA and component certificates
# for local development mTLS. NOT for production use.
#
# Usage: bash scripts/generate-certs.sh
#
# Produces:
#   certs/ca.pem, certs/ca-key.pem          — Root CA
#   certs/ingestion.pem, ingestion-key.pem   — Ingestion API server cert
#   certs/analysis.pem, analysis-key.pem     — Analysis engine server cert
#   certs/sdk-client.pem, sdk-client-key.pem — SDK client cert (for agents)

set -euo pipefail

CERT_DIR="certs"
DAYS=365
KEY_SIZE=4096
CA_SUBJECT="/CN=AgentTransponder-Dev-CA/O=AgentTransponder/OU=Development"

mkdir -p "${CERT_DIR}"

echo "==> Generating root CA"
openssl req -x509 -new -nodes \
    -newkey rsa:${KEY_SIZE} \
    -keyout "${CERT_DIR}/ca-key.pem" \
    -out "${CERT_DIR}/ca.pem" \
    -days ${DAYS} \
    -subj "${CA_SUBJECT}" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

generate_cert() {
    local name=$1
    local cn=$2
    local san=$3
    local usage=$4

    echo "==> Generating ${name} certificate"

    # Create private key and CSR
    openssl req -new -nodes \
        -newkey rsa:${KEY_SIZE} \
        -keyout "${CERT_DIR}/${name}-key.pem" \
        -out "${CERT_DIR}/${name}.csr" \
        -subj "/CN=${cn}/O=AgentTransponder"

    # Create extension file for SAN and usage
    cat > "${CERT_DIR}/${name}.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=${usage}
subjectAltName=${san}
EOF

    # Sign with CA
    openssl x509 -req \
        -in "${CERT_DIR}/${name}.csr" \
        -CA "${CERT_DIR}/ca.pem" \
        -CAkey "${CERT_DIR}/ca-key.pem" \
        -CAcreateserial \
        -out "${CERT_DIR}/${name}.pem" \
        -days ${DAYS} \
        -extfile "${CERT_DIR}/${name}.ext"

    # Cleanup temp files
    rm -f "${CERT_DIR}/${name}.csr" "${CERT_DIR}/${name}.ext"

    echo "    Created: ${CERT_DIR}/${name}.pem, ${CERT_DIR}/${name}-key.pem"
}

# Server certs — for ingestion API and analysis engine
generate_cert "ingestion" "at-ingestion" \
    "DNS:ingestion,DNS:localhost,IP:127.0.0.1" \
    "serverAuth"

generate_cert "analysis" "at-analysis" \
    "DNS:analysis,DNS:localhost,IP:127.0.0.1" \
    "serverAuth"

# Client cert — for SDK to authenticate to ingestion API
generate_cert "sdk-client" "at-sdk-agent" \
    "DNS:localhost,IP:127.0.0.1" \
    "clientAuth"

# Set restrictive permissions on private keys
chmod 600 "${CERT_DIR}"/*-key.pem
chmod 644 "${CERT_DIR}"/*.pem

# Verify the chain
echo ""
echo "==> Verifying certificate chain"
openssl verify -CAfile "${CERT_DIR}/ca.pem" "${CERT_DIR}/ingestion.pem"
openssl verify -CAfile "${CERT_DIR}/ca.pem" "${CERT_DIR}/analysis.pem"
openssl verify -CAfile "${CERT_DIR}/ca.pem" "${CERT_DIR}/sdk-client.pem"

echo ""
echo "✅ All certificates generated in ${CERT_DIR}/"
echo ""
echo "⚠️  These are DEVELOPMENT certificates only."
echo "   For production, use SPIFFE/SPIRE or a proper PKI."
echo ""
echo "Add to .gitignore:"
echo "  certs/"
