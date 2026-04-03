# CLAUDE.md — Agent Transponder

## Project Overview

Agent Transponder is a security-first observability platform for AI agents. It captures telemetry, detects failures, drift, and unsafe behaviors. Think of it as the black box flight recorder for AI agent systems.

## Architecture

This is a hybrid Go + Python project:

- **Go** — ingestion API, metrics exporter, all infrastructure (hot path, security boundaries)
- **Python** — SDK (agent instrumentation library), analysis engine (classifiers/detectors)
- **gRPC** — cross-language service contracts defined in `proto/agenttransponder/v1/`

### Component Map

```
Agent (Python SDK) --mTLS+HMAC--> Ingestion API (Go) --gRPC/mTLS--> Analysis Engine (Python)
                                       |                                    |
                                       v                                    v
                                  Event Store (JSONL)              Metrics Exporter (Go)
                                  Audit Log (hash-chained)              |
                                  Key Manager (envelope enc)            v
                                                                   Prometheus → Grafana
```

## Code Organization

```
cmd/ingestion/          Go ingestion API entry point
cmd/exporter/           Go metrics exporter entry point
internal/
  types/                Canonical event schema (shared across all components)
  eventstore/           EventStore interface + JSONL implementation
  audit/                AuditSink interface + hash-chain implementation
  identity/             IdentityProvider interface + mTLS/self-signed CA implementation
  keymanager/           KeyManager interface + local envelope encryption implementation
  policy/               PolicyEngine interface + YAML config implementation
  redaction/            Redactor interface + regex implementation
  metrics/              Prometheus metric definitions
proto/agenttransponder/v1/   gRPC service definitions (events.proto, analysis.proto)
sdk/                    Python SDK for agent instrumentation
analysis/               Python analysis engine (loop/drift/misuse detectors)
deploy/
  docker/               Hardened Dockerfiles (distroless Go, sandboxed Python)
  docker-compose.yml    Full local stack with network segmentation
config/                 Runtime configuration (ingestion, prometheus, grafana)
scripts/                Certificate generation, helper scripts
```

## Design Principles

1. **Interface-driven**: Every component boundary is a Go interface or gRPC contract. This enables swapping implementations between v0.1.0 (single-node) and v1.0.0 (distributed) without refactoring callers.
2. **Security-first**: mTLS everywhere, HMAC event integrity, hash-chained audit logs, envelope encryption at rest, regex redaction at ingestion time, sandboxed analysis engine.
3. **Zero trust**: No implicit trust between components. Every connection is authenticated and authorized.

## Key Interfaces (in `internal/`)

These are the stable contracts. Implementations swap; interfaces don't.

| Interface         | 0.1.0 Implementation      | 1.0.0 Target                    |
|-------------------|----------------------------|----------------------------------|
| `EventStore`      | Append-only JSONL on disk  | Kafka + S3                       |
| `IdentityProvider`| Self-signed CA, static certs| SPIFFE/SPIRE, short-lived SVIDs |
| `KeyManager`      | Local keyfile, per-bucket DEKs| Vault / Cloud KMS, auto-rotation|
| `AuditSink`       | SHA-256 hash chain         | Merkle tree + Rekor transparency |
| `PolicyEngine`    | YAML config, token bucket  | OPA sidecar, Rego policies       |
| `Redactor`        | Regex pattern matching     | + ML-based PII detection         |

## Build System

- **Taskfile.yml** — build orchestration (`task ci` runs everything)
- **GoReleaser** — signed releases, multi-arch images, SBOMs
- **cosign** — keyless image signing via Sigstore
- **syft** — SBOM generation (SPDX + CycloneDX)
- **grype** — vulnerability scanning
- Docker images: distroless (Go), slim+hardened (Python)

## Common Commands

```bash
task setup          # Install dev dependencies
task certs          # Generate self-signed CA + component certs
task proto          # Generate Go code from protobuf definitions
task lint           # Run all linters (Go + Python + security)
task test           # Run all tests with race detection
task build          # Build Go binaries
task docker         # Build all container images
task ci             # Full CI pipeline locally
task up             # Start local stack via docker-compose
task down           # Stop local stack
```

## Naming Conventions

- Go binaries: `at-ingestion`, `at-exporter`
- Environment variables: `AT_` prefix (e.g., `AT_TLS_CERT`, `AT_LISTEN_ADDR`)
- Container images: `ghcr.io/<owner>/agent-transponder/{ingestion,exporter,analysis}`
- Proto package: `agenttransponder.v1`
- Python packages: `agent_transponder` (SDK), `agent_transponder_analysis` (engine)

## Security Requirements

- TLS 1.3 minimum, no downgrade negotiation
- All containers: read-only rootfs, no-new-privileges, all capabilities dropped
- Analysis engine: no network egress (enforced by Docker network + seccomp)
- Event content is redacted BEFORE persistence — raw sensitive data never hits disk
- Audit log is fsync'd on every write with hash chain integrity
- Key material is zeroed in memory on close/shred

## Testing Guidelines

- Go: `go test -race ./...` — always use race detector
- Python: `pytest` with verbose output
- All PRs must pass: lint (golangci-lint, ruff, bandit, semgrep) + test + build
