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
- **Container base images**: Currently tag-based; builds and scans apply to the
  resolved image, but a future rebuild may resolve different base content.
- **Automated scanning**: Grype runs on every build; critical
  findings fail the pipeline.

## Local data confinement

On Linux and macOS, event storage, analyzer event reads and findings writes,
exporter event/findings reads, cursor persistence, and audit-log I/O use `os.Root`.
The configured directories (and their parent directories at initialization) are
operator-controlled trust anchors. Roots pin the opened directory rather than
re-resolving its pathname for each operation. Absolute paths and symlinks that
escape the root are rejected by the filesystem API, not by a string-prefix check.
Relative symlinks to targets within the same root are allowed; directory walks do
not recurse through directory symlinks. These are storage-root boundaries, not
per-tenant access-control boundaries. Hard links, mounts, special files and an
attacker who already controls the service account are outside this guarantee.
Do not grant untrusted users write access to these directories. Config, policy,
TLS and key-store locations remain explicitly operator-controlled inputs.

Certificate Organization is the tenant identity; ingestion verifies mTLS and
HMAC and replaces event-supplied identity with that certificate identity before
persistence. Tenant IDs are now preserved exactly, including case and internal
spaces. Empty IDs, `.`/`..`, path separators (both slash forms), colons, control
characters and leading/trailing whitespace are rejected. A certificate without
an Organization explicitly receives `_default`. Event-store callers must supply
a valid nonempty tenant ID. There is no implicit lowercasing or replacement of
spaces. Before rollout, check certificate subjects and existing tenant directories:
previously normalized identities may select different directories. Reissue unsafe
certificates or plan an explicit data migration; this change does not rename data.

Cursor keys include the tenant-relative path so equal date filenames cannot share
an offset. Existing basename-only entries for nested tenant files are ignored;
those files will be replayed once after upgrade, potentially repeating findings.
Cursor replacement uses a randomly named, exclusively created file and a confined
rename, so a planted `.cursor.json.tmp` cannot redirect a write. Service data files
remain `0640` and directories `0750` to support the shared service group.

See [the compatibility preflight and migration runbook](docs/tenant-migration.md)
for collision handling, cursor replay, rollback and filesystem boundary limits.
