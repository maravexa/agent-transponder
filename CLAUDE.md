# CLAUDE.md — Agent Transponder

## Project Overview

Agent Transponder is a security-first observability platform for AI agents. It captures telemetry, detects failures, drift, and unsafe behaviors. Think of it as the black box flight recorder for AI agent systems.

The v0.1.0 PoC is functional. Deployment is Ansible-based (single node). Docker Compose is secondary/legacy.

## Architecture

This is a hybrid Go + Python project:

- **Go** — ingestion API, analyzer, metrics exporter, all infrastructure (hot path, security boundaries)
- **Python** — SDK (agent instrumentation library); the analysis engine was rewritten in Go
- **gRPC** — cross-language service contracts defined in `proto/agenttransponder/v1/`

### Component Map

```
Agent SDK (Python)
    │
    │ gRPC + mTLS (:8443)
    ▼
┌─────────────────────────────────┐
│ Ingester (Go)                   │
│ Health :8081 │ Metrics :8082    │
│ Events → JSONL on disk          │
│ Audit → append-only JSONL       │
└─────────┬───────────────────────┘
          │ filesystem
          ▼
┌─────────────────────────────────┐
│ Analyzer (Go)                   │
│ Health :8420                    │
│ Loop, Tool Misuse, Drift detect │
│ Findings → JSONL on disk        │
└─────────┬───────────────────────┘
          │ filesystem
          ▼
┌─────────────────────────────────┐
│ Metrics Exporter (Go)           │
│ /metrics :8430                  │
│ Exposes findings as Prometheus  │
└─────────┬───────────────────────┘
          │ Prometheus scrape
          ▼
┌─────────────────────────────────┐
│ Prometheus (:9090)              │
│ Grafana (:3000)                 │
│ Node Exporter (:9100)           │
└─────────────────────────────────┘
```

## Code Organization

```
cmd/
  ingestion/          Go ingestion API entry point (gRPC :8443)
  analyzer/           Go analysis engine entry point (health :8420)
  exporter/           Go metrics exporter entry point (/metrics :8430)
internal/
  types/              Canonical event schema (shared across all components)
  eventstore/         EventStore interface + JSONL implementation
  audit/              AuditSink interface + hash-chain implementation
  identity/           IdentityProvider interface + mTLS/self-signed CA implementation
  keymanager/         KeyManager interface + local envelope encryption implementation
  policy/             PolicyEngine interface + YAML config implementation
  redaction/          Redactor interface + regex implementation
  metrics/            Prometheus metric definitions
  analyzer/           Analysis engine logic (loop, drift, tool-misuse detectors)
proto/agenttransponder/v1/
  events.proto        SDK → Ingestion gRPC service contract
  analysis.proto      Ingestion → Analysis gRPC service contract
  *.pb.go             Generated Go code (do not edit)
sdk/                  Python SDK for agent instrumentation (ACTIVE — do not archive)
archive/
  analysis-python/    Original Python analysis engine (reference only, replaced by Go)
  test_e2e.py         Original Docker-era e2e test (replaced by ansible/smoke-test.yml)
ansible/
  roles/              Ansible roles (common, hardening, tls, ingester, analyzer,
                        metrics_exporter, prometheus, grafana, node_exporter)
  site.yml            Production deployment playbook
  local.yml           Dev bootstrap playbook (hardening disabled)
  smoke-test.yml      End-to-end smoke test
  inventories/        dev / staging / production inventory files
config/               Runtime configuration files (ingestion.yaml, policy.yaml, etc.)
deploy/
  docker/             Hardened Dockerfiles (secondary for v0.1.0)
  docker-compose.yml  Legacy local stack (replaced by Ansible for v0.1.0)
scripts/              Certificate generation, helper scripts
```

## Canonical Port Assignments

| Service          | Port | Protocol  | Purpose                      |
|------------------|------|-----------|------------------------------|
| Ingester         | 8443 | gRPC+mTLS | Agent event submission       |
| Ingester         | 8081 | HTTP      | Health check                 |
| Ingester         | 8082 | HTTP      | Internal metrics             |
| Analyzer         | 8420 | HTTPS     | Health + API                 |
| Metrics Exporter | 8430 | HTTPS     | Prometheus metrics           |
| Prometheus       | 9090 | HTTPS     | Monitoring                   |
| Grafana          | 3000 | HTTPS     | Dashboards                   |
| Node Exporter    | 9100 | HTTP      | System metrics               |

**Important:** The ingester speaks gRPC (not HTTP REST) on port 8443.

## Metric Prefixes

- **Ingester metrics:** `agent_transponder_*` (e.g., `agent_transponder_active_connections`)
- **Analyzer / Exporter metrics:** `flight_recorder_*` (e.g., `flight_recorder_findings_total`)

Key metrics:
```
flight_recorder_active_sessions
flight_recorder_analyzer_errors_total
flight_recorder_events_ingested_total
flight_recorder_findings_total
flight_recorder_ingestion_latency_seconds_bucket

agent_transponder_active_connections
agent_transponder_active_deks
agent_transponder_analysis_batches_total
agent_transponder_analysis_errors_total
agent_transponder_audit_chain_length
agent_transponder_audit_entries_total
agent_transponder_buckets_active
agent_transponder_build_info
agent_transponder_crypto_shreds_total
agent_transponder_key_rotations_total
```

## Design Principles

1. **Interface-driven**: Every component boundary is a Go interface or gRPC contract. This enables swapping implementations between v0.1.0 (single-node) and v1.0.0 (distributed) without refactoring callers.
2. **Security-first**: mTLS everywhere, HMAC event integrity, hash-chained audit logs, envelope encryption at rest, regex redaction at ingestion time, sandboxed analysis engine.
3. **Zero trust**: No implicit trust between components. Every connection is authenticated and authorized.

## Key Interfaces (in `internal/`)

These are the stable contracts. Implementations swap; interfaces don't.

| Interface         | 0.1.0 Implementation       | 1.0.0 Target                     |
|-------------------|----------------------------|----------------------------------|
| `EventStore`      | Append-only JSONL on disk  | Kafka + S3                       |
| `IdentityProvider`| Self-signed CA, static certs| SPIFFE/SPIRE, short-lived SVIDs |
| `KeyManager`      | Local keyfile, per-bucket DEKs| Vault / Cloud KMS, auto-rotation|
| `AuditSink`       | SHA-256 hash chain         | Merkle tree + Rekor transparency |
| `PolicyEngine`    | YAML config, token bucket  | OPA sidecar, Rego policies       |
| `Redactor`        | Regex pattern matching     | + ML-based PII detection         |

## Ansible Role Pattern

Every Ansible role follows this OS preflight pattern:

1. Verify OS/distribution compatibility (fail early with a clear message)
2. Install required packages
3. Create system user + group (no login shell, no home)
4. Create required directories with correct permissions
5. Deploy TLS certificates
6. Template configuration files
7. Install binary / package
8. Enable + start systemd service

**Config source of truth:** Go config structs (in `cmd/*/`) are authoritative. Ansible templates in `ansible/roles/*/templates/` must match the Go struct field names exactly.

## Build Commands

```bash
# Build all Go binaries → dist/
make build-all

# Deploy to localhost (dev mode, hardening disabled)
make ansible-local

# Deploy to inventory (ENV=dev|staging|production)
make ansible-deploy ENV=dev

# Run smoke test
make smoke-test

# Install Ansible collections
make ansible-deps

# Lint Ansible
make ansible-lint
```

## Python SDK vs. Archived Python

- `sdk/` — **Active code.** Python SDK for agent instrumentation. Do not archive or modify without care.
- `archive/analysis-python/` — **Reference only.** The original Python analysis engine, replaced by the Go implementation in `cmd/analyzer/` and `internal/analyzer/`.

## Build System

- **Makefile** — symlink to `ansible/Makefile`; primary build orchestration
- **Taskfile.yml** — legacy task runner (Docker Compose era)
- **GoReleaser** — signed releases, multi-arch images, SBOMs
- **cosign** — keyless image signing via Sigstore
- **syft** — SBOM generation (SPDX + CycloneDX)
- **grype** — vulnerability scanning

## Naming Conventions

- Go binaries: `at-ingestion`, `at-analyzer`, `at-exporter`
- Environment variables: `AT_` prefix (e.g., `AT_TLS_CERT`, `AT_LISTEN_ADDR`)
- Container images: `ghcr.io/<owner>/agent-transponder/{ingestion,exporter}`
- Proto package: `agenttransponder.v1`
- Python package: `agent_transponder` (SDK)

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
- All PRs must pass: lint (golangci-lint, ruff, bandit, semgrep, ansible-lint) + test + build
