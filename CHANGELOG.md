# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — 2026-04-05

### Added

- **LangChain integration** — `TransponderCallbackHandler` (sync and async variants) maps LangChain callback events to Agent Transponder telemetry. Captures prompts, responses, tool calls, errors, chain metadata, retriever operations, and retries through LangChain's public callback API.
- **Causal attribution fields** — `run_id`, `parent_run_id`, and `tags` added to the Event schema (proto, Go struct, Python dataclass). Enables run-tree reconstruction for replay and failure-cascade analysis. Backward-compatible — old events without these fields are handled gracefully.
- **Findings metrics in exporter** — the metrics exporter now parses findings JSONL and exposes `flight_recorder_findings_total` with `type`, `severity`, and `detector` labels. Previously it only counted lines and file sizes.
- **Grafana dashboard** — provisioned "Agent Transponder" dashboard with findings by type, detection rate over time, findings by severity/detector, storage stats, and system health panels.
- **LangChain demo script** — `examples/langchain_demo.py` runs three scripted scenarios (task loop, tool misuse, goal drift) that exercise the full pipeline end-to-end using `FakeListChatModel` for deterministic, reproducible results. Includes `--live` mode for real LLM exploration.
- **SDK TLS client certificate** — Ansible TLS role now generates an SDK client cert at `/etc/flight-recorder/tls/sdk/`, removing the need for manual `openssl` commands.
- **HMAC debug utility** — `cmd/hmaccheck/` prints canonical JSON and HMAC digest for a test event, useful for diagnosing cross-language serialization mismatches.
- **Proto stub generation** — `make proto-python` target generates Python gRPC stubs. Go stubs regenerated with `run_id`, `parent_run_id`, and `tags` fields.

### Fixed

- **Cross-language HMAC verification** — Go's `ComputeHMAC` now round-trips through `map[string]interface{}` to produce alphabetically sorted keys, matching Python's `json.dumps(sort_keys=True)`. Previously, struct field declaration order caused every SDK-signed event to fail verification.
- **HMAC pipeline ordering** — the ingester now verifies HMAC signatures before overwriting `agent_id` and `tenant_id` from the mTLS certificate identity. Previously, the identity override happened first, causing a mismatch between the signed and verified canonical JSON.
- **Timestamp serialization parity** — Python SDK now strips trailing zeros from fractional seconds and uses `Z` suffix for UTC, matching Go's `time.MarshalJSON` output. A timestamp like `2026-04-05T17:49:11.934990+00:00` is now serialized as `2026-04-05T17:49:11.93499Z`.
- **Event type/severity serialization** — Python SDK now serializes `type` and `severity` as strings (`"prompt"`, `"info"`) instead of integer enum values, matching Go's string constant representation.
- **Proto field coverage** — `protoToEvent` in the ingester now reads `run_id`, `parent_run_id`, and `tags` from incoming protobuf messages. `_event_to_proto` in the Python SDK now sends all fields included in the HMAC signature.
- **Analyzer tenant subdirectory traversal** — the analyzer now walks tenant subdirectories under the events path, fixing the issue where events stored at `events/flight-recorder/*.jsonl` were not found.
- **Ingester config YAML indentation** — the `agents` section in the Ansible ingester template now renders with correct indentation.
- **Exporter variable naming** — Ansible role defaults now use the `exporter_` prefix matching the template variables.

### Changed

- **`omitempty` parity** — Python SDK's `to_dict()` now matches Go's `json:",omitempty"` behavior, excluding zero-valued optional fields from serialization.
- **`received_at` handling** — both sides now handle the `received_at` field consistently in HMAC computation.
- **SDK optional dependencies** — LangChain integration available via `pip install agent-transponder-sdk[langchain]` with `langchain-core>=0.3,<2.0`.

## [0.1.0] — 2026-04-04

### Added

- Initial PoC release.
- Go ingester with gRPC+mTLS event submission, PII/secret redaction, envelope encryption (AES-256-GCM), and SHA-256 hash-chained audit log.
- Go analyzer with loop detection, tool misuse detection, and goal drift detection.
- Go metrics exporter with Prometheus metrics endpoint.
- Python SDK with `Transponder` and `Session` API, HMAC-SHA256 event signing, async buffering, and mTLS support.
- Ansible deployment with roles for common, hardening, TLS, ingester, analyzer, metrics exporter, Prometheus, Grafana, and node exporter.
- Tamper-evident audit trail with integrity verification.
- Signed supply chain with cosign image signing and SBOM generation.
