# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | ✅ Active          |
| < 0.1   | ❌ Not supported   |

## Reporting a Vulnerability

If you discover a security vulnerability in Agent Transponder, please
report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email: **me@maravexa.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)

You should receive an acknowledgment within 48 hours. We aim to provide
a fix or mitigation within 7 days for critical issues.

## Security Architecture

Agent Transponder is designed with a security-first architecture:

- **mTLS everywhere**: All service-to-service communication uses mutual
  TLS. In v0.1.x this uses a self-signed CA; v1.0 targets SPIFFE/SPIRE
  workload identity.
- **Event integrity**: All telemetry events are HMAC-signed at capture
  and verified at ingestion. The event store is append-only.
- **Audit trail**: All data access is logged via a hash-chained audit
  log with tamper detection.
- **Encryption at rest**: Envelope encryption (AES-256-GCM) with
  per-tenant data encryption keys.
- **Sandboxed analysis**: The Python analysis engine runs with no
  network egress, read-only filesystem, dropped capabilities, and
  no-new-privileges.
- **Minimal containers**: Go components use distroless base images.
  Python components have package managers removed at build time.
- **Supply chain**: All images are signed with Sigstore/cosign, SBOMs
  are generated with syft, and vulnerabilities are scanned with grype.

## Supply Chain Verification

Verify any Agent Transponder container image:

```bash
# Verify image signature
cosign verify ghcr.io/<owner>/agent-transponder/ingestion:<tag> \
  --certificate-identity-regexp=".*" \
  --certificate-oidc-issuer-regexp=".*"

# Verify and extract SBOM attestation
cosign verify-attestation ghcr.io/<owner>/agent-transponder/ingestion:<tag> \
  --type spdxjson \
  --certificate-identity-regexp=".*" \
  --certificate-oidc-issuer-regexp=".*" \
  | jq -r '.payload' | base64 -d | jq .
```

## Dependency Management

- **Go**: Dependencies pinned via `go.sum` with checksum verification.
- **Python**: Dependencies compiled with `pip-compile --generate-hashes`
  for deterministic, hash-verified installs.
- **Container base images**: Pinned to specific digests in CI.
- **Automated scanning**: Grype runs on every build; high/critical
  findings fail the pipeline.
