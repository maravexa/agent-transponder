# Agent Transponder

**Black box telemetry and failure detection for AI agents. Security-first.**

Agent Transponder is an observability and safety platform that captures detailed telemetry from AI agent systems to detect failures, drift, unsafe behaviors, and emergent patterns. Inspired by aviation flight recorders, it provides tamper-evident recording, real-time analysis, and production-grade monitoring for any LLM-backed agent.

## Features

- **Structured telemetry capture** — prompts, responses, tool calls, memory operations, reasoning traces, errors, and token usage
- **Failure detection** — task loops, tool misuse, goal drift, hallucination indicators, failure cascades
- **Tamper-evident audit trail** — SHA-256 hash-chained audit log with integrity verification
- **Encryption at rest** — AES-256-GCM envelope encryption with crypto-shredding for secure deletion
- **mTLS everywhere** — mutual TLS on all service boundaries, TLS 1.3 minimum
- **PII/secret redaction** — regex-based scrubbing at ingestion time (before persistence)
- **Prometheus metrics** — cardinality-bounded, aggregate-only (no PII in labels)
- **Signed supply chain** — cosign image signing, SBOM generation (SPDX + CycloneDX), vulnerability scanning

## Quick Start

```bash
# Install task runner (https://taskfile.dev)
go install github.com/go-task/task/v3/cmd/task@latest

# Install dependencies
task setup

# Generate development certificates
task certs

# Build everything
task docker

# Start the full local stack
task up

# View dashboards
open http://localhost:3000  # Grafana
```

## v0.1.0 Architecture (Current)

Single-node deployment via Docker Compose. All component boundaries use Go interfaces
and gRPC contracts so that implementations can be swapped without refactoring callers.

```
┌─────────────────────────────────────────────────────────────────────────┐
│ UNTRUSTED — Agent Runtime                                               │
│                                                                         │
│  ┌──────────────────┐    ┌─────────────────────────────────────────┐    │
│  │  AI Agent Process │───▶│  Python SDK                             │    │
│  │  (any framework)  │    │  • HMAC-SHA256 event signing            │    │
│  └──────────────────┘    │  • mTLS client certificate              │    │
│                           └──────────────────┬──────────────────────┘    │
└──────────────────────────────────────────────┼──────────────────────────┘
                                               │
                                    mTLS + HMAC-signed events
                                               │
┌──────────────────────────────────────────────┼──────────────────────────┐
│ TRUSTED — Agent Transponder Core             ▼                          │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  Ingestion API (Go)                                              │   │
│  │  • mTLS termination + cert identity extraction                   │   │
│  │  • HMAC verification                                             │   │
│  │  • JSON schema validation                                        │   │
│  │  • Regex + configurable redaction                                │   │
│  │  • Token bucket rate limiting per agent                          │   │
│  └──────────┬──────────────────┬──────────────────┬─────────────────┘   │
│             │                  │                  │                      │
│             ▼                  ▼                  ▼                      │
│  ┌──────────────────┐  ┌──────────────┐  ┌──────────────────────────┐   │
│  │  Event Store     │  │  Audit Log   │  │  Analysis Engine (Python) │  │
│  │  (JSONL)         │  │  (hash chain)│  │  • Loop detection         │  │
│  │  • Append-only   │  │  • SHA-256   │  │  • Tool misuse classifier │  │
│  │  • AES-256-GCM   │  │  • fsync     │  │  • Drift scoring          │  │
│  │  • Per-tenant    │  │  • Separate  │  │  • Failure cascades       │  │
│  │    buckets       │  │    volume    │  │  • Sandboxed (no egress)  │  │
│  │  • Crypto-shred  │  │  • Tamper    │  └─────────────┬────────────┘   │
│  │    on TTL expiry │  │    evident   │                │                 │
│  └──────────────────┘  └──────────────┘                │                 │
│                                                        │                 │
│  ┌─────────────────────────────────────────────────────▼─────────────┐   │
│  │  Metrics Exporter (Go)                                            │   │
│  │  • Prometheus /metrics endpoint                                   │   │
│  │  • Aggregate only — no PII in labels                              │   │
│  │  • Cardinality guards on all label dimensions                     │   │
│  └──────────────────────────────────┬────────────────────────────────┘   │
└─────────────────────────────────────┼───────────────────────────────────┘
                                      │
┌─────────────────────────────────────┼───────────────────────────────────┐
│ OBSERVABILITY PLANE                 ▼                                    │
│                                                                         │
│  ┌──────────────────┐         ┌──────────────────┐                      │
│  │  Prometheus       │────────▶│  Grafana          │                     │
│  │  • Scrape /metrics│         │  • Provisioned    │                     │
│  │  • 7d retention   │         │    dashboards     │                     │
│  └──────────────────┘         └──────────────────┘                      │
└─────────────────────────────────────────────────────────────────────────┘

Deployment: docker-compose │ single node
Security:   self-signed CA │ hash-chain audit │ local envelope encryption
Build:      GoReleaser │ cosign signing │ syft SBOM │ grype vuln scan
```

## v1.0.0 Architecture (Target)

Distributed Kubernetes deployment with full zero trust. Same interfaces,
production-grade implementations behind them.

```
┌─────────────────────────────────────────────────────────────────────────┐
│ UNTRUSTED — Agent Fleet (Kubernetes Pods)                               │
│                                                                         │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐                        │
│  │ Agent Pod 1│  │ Agent Pod 2│  │ Agent Pod N│   Each pod gets a      │
│  │  SDK+SVID  │  │  SDK+SVID  │  │  SDK+SVID  │   short-lived SPIFFE   │
│  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘   identity (SVID)      │
└────────┼───────────────┼───────────────┼────────────────────────────────┘
         │               │               │    ┌────────────────────────┐
         └───────────────┼───────────────┘    │  SPIFFE / SPIRE        │
              mTLS (SVID) │                   │  Workload identity     │
                          ▼                   │  issuer                │
┌─────────────────────────────────────────────┴───────────────────────────┐
│ INGESTION TIER (Go, horizontally scaled)                                │
│                                                                         │
│  ┌──────────────────────────┐    ┌───────────────────────────────────┐  │
│  │  Ingestion API × N       │◀──▶│  OPA Sidecar                      │  │
│  │  (behind L4 load balancer)│    │  • Per-agent authorization       │  │
│  │  • SVID-based mTLS       │    │  • Rate limit + quota policies   │  │
│  └──────┬───────────────────┘    └───────────────────────────────────┘  │
│         │                                                               │
│  ┌──────▼───────────┐  ┌─────────────────┐  ┌────────────────────────┐ │
│  │  KMS Integration  │  │  Audit Pipeline  │  │  Retention Controller  │ │
│  │  Vault/AWS/GCP    │  │  Merkle tree +   │  │  TTL enforcement       │ │
│  │  KEK management   │  │  Rekor           │  │  Crypto-shredding      │ │
│  │  Auto key rotation│  │  transparency    │  │  via KMS               │ │
│  └──────────────────┘  └─────────────────┘  └────────────────────────┘ │
└──────────────────────────────────┬──────────────────────────────────────┘
                                   │
┌──────────────────────────────────▼──────────────────────────────────────┐
│ EVENT STREAM                                                            │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  Kafka (encrypted, ACL-enforced)                                 │   │
│  │  • Partitioned by tenant + agent-class                           │   │
│  │  • Schema registry for event validation                          │   │
│  │  • TLS in transit, encryption at rest                            │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────┬──────────────────────────────────────┘
                                   │
┌──────────────────────────────────▼──────────────────────────────────────┐
│ ANALYSIS TIER (Python, horizontally scaled)                             │
│                                                                         │
│  ┌────────────────────┐  ┌────────────────┐  ┌───────────────────────┐ │
│  │ Analysis Workers×N  │  │  Object Storage │  │  Alert Manager (Go)   │ │
│  │ (K8s Jobs, HPA)     │  │  S3/GCS/MinIO   │  │  • Drift alerts       │ │
│  │ • Consumer groups   │  │  • SSE w/ CMK   │  │  • Failure cascades   │ │
│  │ • gVisor sandbox    │  │  • Versioning   │  │  • PagerDuty/webhook  │ │
│  │ • NetworkPolicy:    │  │  • Lifecycle    │  │  • Per-tenant config  │ │
│  │   no egress         │  │    policies     │  │                       │ │
│  └────────────────────┘  └────────────────┘  └───────────────────────┘ │
└──────────────────────────────────┬──────────────────────────────────────┘
                                   │
┌──────────────────────────────────▼──────────────────────────────────────┐
│ OBSERVABILITY PLANE                                                     │
│                                                                         │
│  ┌──────────────┐  ┌────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ Prometheus +  │  │Grafana │  │OpenTelemetry │  │ Loki / Elastic   │  │
│  │ Thanos (HA)   │  │(multi- │  │(traces+logs) │  │ (audit log       │  │
│  │               │  │tenant) │  │              │  │  search)         │  │
│  └──────────────┘  └────────┘  └──────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘

Deployment: Kubernetes │ Helm charts │ GitOps (ArgoCD/Flux)
Security:   SPIFFE/SPIRE │ OPA │ KMS envelope encryption │ Rekor transparency
Scale:      HPA on ingestion+analysis │ Kafka partitioning │ Thanos federation
```

## Evolution Path

The v0.1.0 → v1.0.0 upgrade swaps implementations behind stable interfaces:

| Interface           | v0.1.0                           | v1.0.0                               |
|---------------------|----------------------------------|--------------------------------------|
| `EventStore`        | Append-only JSONL on local disk  | Kafka topics + S3 persistence        |
| `IdentityProvider`  | Self-signed CA, static certs     | SPIFFE/SPIRE, short-lived SVIDs      |
| `KeyManager`        | Local keyfile, per-bucket DEKs   | Vault / Cloud KMS, auto-rotation     |
| `AuditSink`         | SHA-256 hash chain               | Merkle tree + Rekor transparency log |
| `PolicyEngine`      | YAML config, token bucket        | OPA sidecar, Rego policies           |
| `AnalysisRunner`    | Single gRPC worker, Unix socket  | K8s Jobs, consumer groups, HPA       |

## Project Structure

```
cmd/
  ingestion/            Go ingestion API server
  exporter/             Go Prometheus metrics exporter
internal/
  types/                Canonical event schema
  eventstore/           EventStore interface + JSONL implementation
  audit/                AuditSink interface + hash-chain implementation
  identity/             IdentityProvider interface + mTLS implementation
  keymanager/           KeyManager interface + local encryption implementation
  policy/               PolicyEngine interface + config-based implementation
  redaction/            Redactor interface + regex implementation
  metrics/              Prometheus metric definitions
proto/agenttransponder/v1/
  events.proto          SDK → Ingestion gRPC service contract
  analysis.proto        Ingestion → Analysis gRPC service contract
sdk/                    Python SDK for agent instrumentation
analysis/               Python analysis engine
deploy/
  docker/               Hardened Dockerfiles
  docker-compose.yml    Full local development stack
config/                 Runtime configuration files
scripts/                Certificate generation and helper scripts
```

## Security

See [SECURITY.md](SECURITY.md) for the full security policy, vulnerability reporting process, and supply chain verification instructions.

### Supply Chain Verification

```bash
# Verify image signature
cosign verify ghcr.io/<owner>/agent-transponder/ingestion:<tag> \
  --certificate-identity-regexp=".*" \
  --certificate-oidc-issuer-regexp=".*"

# Verify SBOM attestation
cosign verify-attestation ghcr.io/<owner>/agent-transponder/ingestion:<tag> \
  --type spdxjson
```

## Development

```bash
task setup          # Install dev dependencies
task certs          # Generate development certificates
task proto          # Generate gRPC code from protobuf definitions
task lint           # Lint everything (Go + Python + security)
task test           # Run all tests with race detection
task build          # Build Go binaries
task docker         # Build all container images
task ci             # Run the full CI pipeline locally
task up             # Start the local stack
task down           # Stop the local stack
```

## License

[TBD]
