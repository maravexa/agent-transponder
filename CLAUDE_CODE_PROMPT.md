# Claude Code Prompt — Agent Transponder: Ingestion Server, Python SDK, and Analysis Engine

## Context

You are working on `agent-transponder`, a security-first observability platform for AI agents. The project already has:

- **Full build pipeline**: Taskfile, GoReleaser, GitHub Actions CI/CD, cosign signing, SBOM generation, hardened Dockerfiles, docker-compose with network segmentation
- **Core Go interfaces and 0.1.0 implementations** in `internal/`:
  - `types/event.go` — canonical event schema with HMAC computation
  - `eventstore/` — `Store` interface + `JSONLStore` (append-only JSONL)
  - `audit/` — `Sink` interface + `HashChainSink` (SHA-256 hash chain, fsync per write)
  - `identity/` — `Provider` interface + `TLSProvider` (self-signed CA, TLS 1.3, SAN-based identity)
  - `keymanager/` — `Manager` interface + `LocalManager` (AES-256-GCM envelope encryption, crypto-shredding)
  - `policy/` — `Engine` interface + `ConfigEngine` (YAML rules, token bucket rate limiting)
  - `redaction/` — `Redactor` interface + `RegexRedactor` (14 built-in patterns for secrets/PII)
  - `metrics/` — Prometheus `Collector` with cardinality-bounded metrics
- **gRPC service definitions** in `proto/agenttransponder/v1/`:
  - `events.proto` — `EventIngestion` service (SDK → Ingestion)
  - `analysis.proto` — `AnalysisService` service (Ingestion → Analysis Engine)
- **CLAUDE.md** and **README.md** with full project documentation

Read CLAUDE.md first for the full project context, naming conventions, and design principles.

## Your Task

Build three components that wire everything together into a working system:

### 1. Go Ingestion Server (`cmd/ingestion/main.go` + supporting files)

This is the central hub. It must:

**Server setup:**
- Load configuration from YAML file (`config/ingestion.yaml`) with env var overrides using the `AT_` prefix
- Initialize all six subsystems: IdentityProvider, EventStore, AuditSink, KeyManager, PolicyEngine, Redactor
- Start a gRPC server on `:8443` with mTLS from the IdentityProvider
- Start a plaintext health check HTTP server on `:8081` (localhost only) with `/healthz` and `/readyz` endpoints
- Start Prometheus metrics HTTP server on `:9090` with the metrics Collector
- Graceful shutdown on SIGTERM/SIGINT — flush event store, flush audit log, zero key material

**Request pipeline (for each incoming event via gRPC `IngestEvent`):**
1. Extract agent identity from the mTLS connection (via `IdentityProvider.Identify`)
2. Evaluate policy (via `PolicyEngine.Evaluate`) — reject or throttle if denied
3. Verify event HMAC (via `event.VerifyHMAC` with the agent's key)
4. Validate JSON schema (event type is known, required fields present)
5. Apply redaction (via `Redactor.Redact`) — scrub before persistence
6. Set `ReceivedAt` timestamp and `RedactedFields`
7. Append to event store (via `EventStore.Append`)
8. Log to audit trail (via `AuditSink.Log`)
9. Forward to analysis engine asynchronously (via gRPC `AnalysisService.AnalyzeBatch` — non-blocking, batched)
10. Increment Prometheus metrics
11. Return `IngestEventResponse` with accepted/rejected status

**Analysis forwarding:**
- Buffer events in memory (bounded channel, e.g., 1000 events)
- Batch and send to the analysis engine every N seconds or when the buffer is full
- If the analysis engine is unavailable, log the error but don't block ingestion
- Circuit breaker: if analysis fails 5 times consecutively, stop forwarding for 30 seconds

**Configuration file (`config/ingestion.yaml`):**
```yaml
server:
  listen_addr: ":8443"
  health_addr: ":8081"
  metrics_addr: ":9090"

tls:
  ca_path: "/etc/at/certs/ca.pem"
  cert_path: "/etc/at/certs/server.pem"
  key_path: "/etc/at/certs/server-key.pem"

event_store:
  path: "/data/events"

audit:
  path: "/data/audit/audit.jsonl"

analysis:
  addr: "analysis:50051"
  batch_size: 50
  flush_interval: "5s"
  circuit_breaker_threshold: 5
  circuit_breaker_cooldown: "30s"

retention:
  default_ttl: "72h"
  check_interval: "1h"

redaction:
  # Additional patterns beyond the built-in defaults
  custom_patterns: []

policy:
  config_path: "/etc/at/policy.yaml"

# Per-agent HMAC keys (in production, load from a secrets manager)
agents:
  at-sdk-agent:
    hmac_key: "base64-encoded-key-here"

logging:
  format: "json"  # "json" or "text"
  level: "info"
```

**Also create:**
- `config/policy.yaml` — example policy config with default rate limits
- `config/prometheus.yml` — Prometheus scrape config targeting the exporter
- `cmd/ingestion/config.go` — config struct and loading logic

### 2. Python SDK (`sdk/`)

The SDK is what agent developers import to instrument their agents. It must be lightweight, intuitive, and handle all security concerns transparently.

**Package structure:**
```
sdk/
  pyproject.toml
  requirements.in
  flight_recorder/         # Note: import name stays `flight_recorder` for brevity (aliased in pyproject.toml as agent-transponder-sdk)
    __init__.py            # Public API: Transponder, Event, configure()
    client.py              # gRPC client with mTLS and connection management
    events.py              # Event dataclasses matching the proto schema
    hmac.py                # HMAC-SHA256 signing
    interceptors.py        # Framework integrations (LangChain, generic)
    config.py              # SDK configuration
```

**Public API (keep it simple):**

```python
from agent_transponder import Transponder

# Initialize with mTLS certs and HMAC key
tp = Transponder(
    endpoint="localhost:8443",
    ca_cert="/path/to/ca.pem",
    client_cert="/path/to/client.pem",
    client_key="/path/to/client-key.pem",
    hmac_key=b"shared-secret",
    agent_id="my-agent",
    tenant_id="my-team",
)

# Record events
with tp.session() as session:
    session.record_prompt("What is the weather?", role="user", model="gpt-4")
    session.record_response("The weather is sunny.", finish_reason="stop", tokens=12)
    session.record_tool_call("weather_api", args={"city": "NYC"}, result={"temp": 72}, success=True)
    session.record_error("timeout", message="API call timed out", retryable=True)

# Context manager auto-flushes on exit
# Or manually: tp.flush() and tp.close()
```

**Requirements:**
- `grpcio` and `grpcio-tools` for gRPC
- HMAC-SHA256 signing using stdlib `hmac` module — no extra crypto deps
- Automatic retry with exponential backoff on transient gRPC errors
- Async event buffering — `record_*` methods return immediately, events sent in background
- Thread-safe — multiple threads can record events concurrently
- UUIDv7 for event IDs (time-ordered)
- Session context manager for grouping related events
- Graceful shutdown — flush pending events on `close()`

### 3. Python Analysis Engine (`analysis/`)

The analysis engine receives batches of events and runs classifiers to detect agent failure modes.

**Package structure:**
```
analysis/
  pyproject.toml
  requirements.in
  flight_recorder_analysis/    # Import name
    __init__.py
    server.py                  # gRPC server implementing AnalysisService
    detectors/
      __init__.py
      base.py                  # Abstract base detector class
      loop_detector.py         # Task loop detection (sequence repetition)
      tool_misuse.py           # Tool misuse detection (error rates, invalid patterns)
      drift_detector.py        # Goal drift scoring (cosine similarity on prompts)
    config.py                  # Analysis engine configuration
```

**Detector interface:**

```python
class BaseDetector(ABC):
    @abstractmethod
    def detect(self, events: list[Event]) -> list[Detection]:
        """Analyze events and return any detections."""
        ...

    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def version(self) -> str: ...

    @property
    @abstractmethod
    def detection_type(self) -> DetectionType: ...
```

**Detector implementations:**

- **LoopDetector**: Detects repeated sequences of tool calls or prompt/response patterns. Uses sliding window comparison — if the same sequence of N events repeats M times, flag it. Configurable thresholds for sequence length and repetition count.

- **ToolMisuseDetector**: Flags agents that call the same tool repeatedly with the same arguments and fail, agents that retry more than N times, or agents that call tools with known-invalid argument patterns.

- **DriftDetector**: Computes cosine similarity between the initial session prompt and subsequent prompts. If the similarity drops below a threshold, the agent may be drifting from its original goal. Use basic TF-IDF or token overlap for v0.1.0 (no ML model dependencies).

**gRPC server:**
- Implement `AnalysisService.AnalyzeBatch` — run all detectors on the event batch, aggregate results
- Implement `AnalysisService.ListDetectors` — return metadata about loaded detectors
- mTLS on `:50051` using certs from environment variables
- Structured JSON logging

## Implementation Notes

- **Do NOT generate protobuf Go/Python code** — just set up the build commands in the Taskfile. The proto definitions already exist.
- **Use `log/slog`** for structured logging in Go (stdlib since 1.21). No third-party logging frameworks.
- **Use `context.Context`** everywhere in Go — all operations should be cancellable.
- **Run `go mod tidy`** after adding imports to ensure go.sum is updated.
- **Python logging**: use stdlib `logging` with JSON formatter for production.
- **Error handling in Go**: wrap errors with `fmt.Errorf("context: %w", err)` for stack traces. Never silently discard errors.
- **Test files**: Create `_test.go` files for the ingestion pipeline (at minimum: HMAC verification, redaction, policy evaluation). Create `test_*.py` files for the SDK and analysis engine.
- Respect all naming conventions in CLAUDE.md (AT_ prefix, at-ingestion binary name, etc.)

## Files to Create

```
cmd/ingestion/main.go           # Server entry point and wiring
cmd/ingestion/config.go         # Config structs and YAML loading
cmd/ingestion/pipeline.go       # Event processing pipeline
cmd/ingestion/analysis.go       # Analysis engine client with batching + circuit breaker
cmd/ingestion/pipeline_test.go  # Pipeline unit tests

config/ingestion.yaml           # Default ingestion config
config/policy.yaml              # Default policy config
config/prometheus.yml           # Prometheus scrape configuration
config/grafana/provisioning/datasources/prometheus.yml
config/grafana/provisioning/dashboards/agent-transponder.json

sdk/pyproject.toml
sdk/requirements.in
sdk/agent_transponder/__init__.py
sdk/agent_transponder/client.py
sdk/agent_transponder/events.py
sdk/agent_transponder/hmac.py
sdk/agent_transponder/config.py
sdk/tests/test_events.py
sdk/tests/test_hmac.py

analysis/pyproject.toml
analysis/requirements.in
analysis/flight_recorder_analysis/__init__.py
analysis/flight_recorder_analysis/server.py
analysis/flight_recorder_analysis/config.py
analysis/flight_recorder_analysis/detectors/__init__.py
analysis/flight_recorder_analysis/detectors/base.py
analysis/flight_recorder_analysis/detectors/loop_detector.py
analysis/flight_recorder_analysis/detectors/tool_misuse.py
analysis/flight_recorder_analysis/detectors/drift_detector.py
analysis/tests/test_loop_detector.py
analysis/tests/test_tool_misuse.py
```

## Verification

When done, the following should work:

```bash
# Go builds cleanly
go build ./cmd/ingestion/
go vet ./...
go test -race ./...

# Python tests pass
cd sdk && python -m pytest tests/ -v
cd analysis && python -m pytest tests/ -v

# Docker images build
task docker

# Full stack starts
task certs && task up

# Health check responds
curl http://localhost:8081/healthz
```
