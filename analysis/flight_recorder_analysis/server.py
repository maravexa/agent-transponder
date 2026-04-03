"""
gRPC server for the Flight Recorder Analysis Engine.

The gRPC / proto-stub imports are intentionally lazy so that this module can
be imported (and the detectors exercised) without ``grpcio`` or generated
proto stubs being installed.  The ``serve()`` entry point will raise an
informative ``RuntimeError`` if the required dependencies are missing.

Environment variables (all ``AT_`` prefixed):

    AT_LISTEN_ADDR   gRPC listen address, default ``[::]:50052``
    AT_TLS_CERT      Path to PEM-encoded server certificate
    AT_TLS_KEY       Path to PEM-encoded server private key
    AT_TLS_CA        Path to PEM-encoded CA certificate (for mTLS client auth)
"""

from __future__ import annotations

import json
import logging
import sys
import time
from typing import Any

from flight_recorder_analysis.config import AnalysisConfig
from flight_recorder_analysis.detectors import DriftDetector, LoopDetector, ToolMisuseDetector
from flight_recorder_analysis.detectors.base import BaseDetector
from flight_recorder_analysis.models import Detection, DetectionType, Event, EventType, Severity

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Structured JSON logging setup
# ---------------------------------------------------------------------------


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def _configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_JsonFormatter())
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.handlers.clear()
    root.addHandler(handler)


# ---------------------------------------------------------------------------
# Proto ↔ dataclass conversion helpers
# ---------------------------------------------------------------------------


def _proto_event_to_dataclass(pb_event: Any) -> Event:
    """Convert a proto ``Event`` message to a plain :class:`Event` dataclass."""
    # EventType enum name → lowercase string
    type_name = pb_event.type.name.removeprefix("EVENT_TYPE_").lower()
    sev_name = pb_event.severity.name.removeprefix("SEVERITY_").lower()

    prompt = None
    if pb_event.HasField("prompt"):
        prompt = {
            "content": pb_event.prompt.content,
            "role": pb_event.prompt.role,
            "token_count": pb_event.prompt.token_count,
        }

    response = None
    if pb_event.HasField("response"):
        response = {
            "content": pb_event.response.content,
            "finish_reason": pb_event.response.finish_reason,
            "token_count": pb_event.response.token_count,
        }

    tool_call = None
    if pb_event.HasField("tool_call"):
        tc = pb_event.tool_call
        tool_call = {
            "tool_name": tc.tool_name,
            "arguments": dict(tc.arguments) if tc.arguments else {},
            "result": dict(tc.result) if tc.result else {},
            "success": tc.success,
            "error_msg": tc.error_msg,
            "retry_count": tc.retry_count,
        }

    memory = None
    if pb_event.HasField("memory"):
        memory = {
            "operation": pb_event.memory.operation,
            "key": pb_event.memory.key,
            "value": pb_event.memory.value,
        }

    reasoning = None
    if pb_event.HasField("reasoning"):
        reasoning = {
            "step": pb_event.reasoning.step,
            "content": pb_event.reasoning.content,
        }

    error = None
    if pb_event.HasField("error"):
        error = {
            "code": pb_event.error.code,
            "message": pb_event.error.message,
            "stacktrace": pb_event.error.stacktrace,
            "retryable": pb_event.error.retryable,
        }

    ts = pb_event.timestamp.seconds + pb_event.timestamp.nanos / 1e9

    return Event(
        id=pb_event.id,
        session_id=pb_event.session_id,
        agent_id=pb_event.agent_id,
        tenant_id=pb_event.tenant_id,
        type=type_name,
        severity=sev_name,
        timestamp=ts,
        prompt=prompt,
        response=response,
        tool_call=tool_call,
        memory=memory,
        reasoning=reasoning,
        error=error,
        model=pb_event.model or None,
        labels=dict(pb_event.labels),
    )


def _detection_to_proto(det: Detection, pb_mod: Any) -> Any:
    """Convert a :class:`Detection` dataclass to the proto ``Detection`` message."""
    dt_map = {
        DetectionType.TASK_LOOP: pb_mod.DETECTION_TYPE_TASK_LOOP,
        DetectionType.TOOL_MISUSE: pb_mod.DETECTION_TYPE_TOOL_MISUSE,
        DetectionType.GOAL_DRIFT: pb_mod.DETECTION_TYPE_GOAL_DRIFT,
        DetectionType.HALLUCINATION: pb_mod.DETECTION_TYPE_HALLUCINATION,
        DetectionType.FAILURE_CASCADE: pb_mod.DETECTION_TYPE_FAILURE_CASCADE,
        DetectionType.REWARD_HACKING: pb_mod.DETECTION_TYPE_REWARD_HACKING,
        DetectionType.PERSONALITY_DRIFT: pb_mod.DETECTION_TYPE_PERSONALITY_DRIFT,
    }
    sev_map = {
        Severity.DEBUG: pb_mod.SEVERITY_DEBUG,
        Severity.INFO: pb_mod.SEVERITY_INFO,
        Severity.WARNING: pb_mod.SEVERITY_WARNING,
        Severity.ERROR: pb_mod.SEVERITY_ERROR,
        Severity.CRITICAL: pb_mod.SEVERITY_CRITICAL,
    }
    dt_val = dt_map.get(det.type, pb_mod.DETECTION_TYPE_UNSPECIFIED)  # type: ignore[arg-type]
    sev_val = sev_map.get(det.severity, pb_mod.SEVERITY_UNSPECIFIED)  # type: ignore[arg-type]
    return pb_mod.Detection(
        type=dt_val,
        severity=sev_val,
        confidence=det.confidence,
        message=det.message,
        event_ids=det.event_ids,
        evidence=det.evidence,
    )


# ---------------------------------------------------------------------------
# gRPC servicer
# ---------------------------------------------------------------------------


def _build_servicer_class(analysis_pb2: Any, analysis_pb2_grpc: Any) -> type:
    """
    Dynamically build the gRPC servicer class so we can inject the proto
    modules at server-start time (not at import time).
    """

    class AnalysisServicer(analysis_pb2_grpc.AnalysisServiceServicer):
        def __init__(self, detectors: list[BaseDetector]) -> None:
            self._detectors = detectors

        def AnalyzeBatch(self, request: Any, context: Any) -> Any:
            t0 = time.perf_counter()
            logger.info(
                json.dumps(
                    {
                        "event": "analyze_batch",
                        "session_id": request.session_id,
                        "agent_id": request.agent_id,
                        "tenant_id": request.tenant_id,
                        "event_count": len(request.events),
                    }
                )
            )

            events = [_proto_event_to_dataclass(e) for e in request.events]
            # Sort by timestamp to guarantee ordering assumptions in detectors.
            events.sort(key=lambda e: e.timestamp)

            all_detections: list[Detection] = []
            latencies: dict[str, float] = {}

            for detector in self._detectors:
                dt0 = time.perf_counter()
                try:
                    found = detector.detect(events)
                    all_detections.extend(found)
                except Exception:
                    logger.exception(
                        json.dumps({"event": "detector_error", "detector": detector.name})
                    )
                    found = []
                latencies[detector.name] = round((time.perf_counter() - dt0) * 1000, 2)

            elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
            logger.info(
                json.dumps(
                    {
                        "event": "analyze_batch_done",
                        "session_id": request.session_id,
                        "detections": len(all_detections),
                        "elapsed_ms": elapsed_ms,
                        "detector_latencies_ms": latencies,
                    }
                )
            )

            from google.protobuf.timestamp_pb2 import Timestamp  # type: ignore[import]

            ts = Timestamp()
            ts.GetCurrentTime()

            metadata = analysis_pb2.AnalysisMetadata(
                analyzed_at=ts,
                events_processed=len(events),
                detections_found=len(all_detections),
                detector_latencies_ms=latencies,
            )

            proto_detections = [
                _detection_to_proto(d, analysis_pb2) for d in all_detections
            ]
            return analysis_pb2.AnalyzeBatchResponse(
                detections=proto_detections,
                metadata=metadata,
            )

        def ListDetectors(self, request: Any, context: Any) -> Any:
            dt_map = {
                DetectionType.TASK_LOOP: analysis_pb2.DETECTION_TYPE_TASK_LOOP,
                DetectionType.TOOL_MISUSE: analysis_pb2.DETECTION_TYPE_TOOL_MISUSE,
                DetectionType.GOAL_DRIFT: analysis_pb2.DETECTION_TYPE_GOAL_DRIFT,
                DetectionType.HALLUCINATION: analysis_pb2.DETECTION_TYPE_HALLUCINATION,
                DetectionType.FAILURE_CASCADE: analysis_pb2.DETECTION_TYPE_FAILURE_CASCADE,
                DetectionType.REWARD_HACKING: analysis_pb2.DETECTION_TYPE_REWARD_HACKING,
                DetectionType.PERSONALITY_DRIFT: analysis_pb2.DETECTION_TYPE_PERSONALITY_DRIFT,
            }
            infos = [
                analysis_pb2.DetectorInfo(
                    name=d.name,
                    version=d.version,
                    type=dt_map.get(d.detection_type, analysis_pb2.DETECTION_TYPE_UNSPECIFIED),
                    enabled=True,
                    description=d.description,
                )
                for d in self._detectors
            ]
            return analysis_pb2.ListDetectorsResponse(detectors=infos)

    return AnalysisServicer


# ---------------------------------------------------------------------------
# Server entry point
# ---------------------------------------------------------------------------


def build_detectors(cfg: AnalysisConfig) -> list[BaseDetector]:
    """Instantiate all detectors from *cfg*."""
    return [
        LoopDetector(cfg.loop),
        ToolMisuseDetector(cfg.tool_misuse),
        DriftDetector(cfg.drift),
    ]


def serve(cfg: AnalysisConfig | None = None) -> None:
    """
    Start the gRPC server.

    Raises
    ------
    RuntimeError
        If ``grpcio`` or the generated proto stubs cannot be imported.
    """
    _configure_logging()
    cfg = cfg or AnalysisConfig()

    # Lazy import — keeps the module importable without grpcio installed.
    try:
        import grpc  # type: ignore[import]
        from concurrent import futures
    except ImportError as exc:
        raise RuntimeError(
            "grpcio is required to run the server. "
            "Install it with: pip install grpcio"
        ) from exc

    # Proto stubs are generated into the same package directory by `task proto`.
    try:
        from flight_recorder_analysis.proto import (  # type: ignore[import]
            analysis_pb2,
            analysis_pb2_grpc,
        )
    except ImportError as exc:
        raise RuntimeError(
            "Generated proto stubs not found. Run `task proto` to generate them."
        ) from exc

    detectors = build_detectors(cfg)
    AnalysisServicer = _build_servicer_class(analysis_pb2, analysis_pb2_grpc)
    servicer = AnalysisServicer(detectors)

    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=10),
        options=[
            ("grpc.max_receive_message_length", 32 * 1024 * 1024),  # 32 MiB
            ("grpc.max_send_message_length", 32 * 1024 * 1024),
        ],
    )
    analysis_pb2_grpc.add_AnalysisServiceServicer_to_server(servicer, server)

    if cfg.mtls_enabled:
        logger.info(json.dumps({"event": "tls_mode", "mode": "mtls"}))
        with open(cfg.tls_cert, "rb") as f:
            cert_chain = f.read()
        with open(cfg.tls_key, "rb") as f:
            private_key = f.read()
        with open(cfg.tls_ca, "rb") as f:
            root_ca = f.read()
        creds = grpc.ssl_server_credentials(
            [(private_key, cert_chain)],
            root_certificates=root_ca,
            require_client_auth=True,
        )
        server.add_secure_port(cfg.listen_addr, creds)
    else:
        logger.warning(
            json.dumps(
                {
                    "event": "tls_mode",
                    "mode": "insecure",
                    "warning": "mTLS is disabled — do not use in production",
                }
            )
        )
        server.add_insecure_port(cfg.listen_addr)

    logger.info(json.dumps({"event": "server_starting", "addr": cfg.listen_addr}))
    server.start()
    logger.info(
        json.dumps(
            {
                "event": "server_ready",
                "addr": cfg.listen_addr,
                "detectors": [d.name for d in detectors],
            }
        )
    )

    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        logger.info(json.dumps({"event": "server_stopping"}))
        server.stop(grace=5)


if __name__ == "__main__":
    serve()
