"""
gRPC client for the Agent Transponder ingestion API.

gRPC imports are lazy so this module can be imported in environments where
grpcio is not installed (e.g. during unit tests that don't touch transport).
"""
from __future__ import annotations

import logging
import queue
import threading
import time
from typing import TYPE_CHECKING

from .config import TransponderConfig
from .events import Event

if TYPE_CHECKING:
    pass  # grpc types only used at runtime

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sentinel used to signal the background thread to stop
# ---------------------------------------------------------------------------
_STOP = object()


class GrpcTransport:
    """Thin wrapper around the gRPC channel and generated stub.

    Constructed lazily on first use so imports don't fail when grpc is absent.
    """

    def __init__(self, cfg: TransponderConfig) -> None:
        self._cfg = cfg
        self._channel = None
        self._stub = None
        self._lock = threading.Lock()

    def _ensure_connected(self) -> None:
        """Create the gRPC channel (and stub) if not already done."""
        if self._channel is not None:
            return

        try:
            import grpc  # type: ignore[import]
        except ImportError as exc:
            raise RuntimeError(
                "grpcio is not installed. "
                "Install it with: pip install grpcio"
            ) from exc

        cfg = self._cfg

        if cfg.ca_cert and cfg.client_cert and cfg.client_key:
            # mTLS
            with open(cfg.ca_cert, "rb") as fh:
                root_certs = fh.read()
            with open(cfg.client_cert, "rb") as fh:
                cert_chain = fh.read()
            with open(cfg.client_key, "rb") as fh:
                private_key = fh.read()

            credentials = grpc.ssl_channel_credentials(
                root_certificates=root_certs,
                private_key=private_key,
                certificate_chain=cert_chain,
            )
            channel = grpc.secure_channel(cfg.endpoint, credentials)
        else:
            # Insecure — development only
            logger.warning(
                "No TLS certificates configured — using insecure channel. "
                "Do NOT use in production."
            )
            channel = grpc.insecure_channel(cfg.endpoint)

        self._channel = channel
        # The generated proto stubs are expected to be importable as:
        #   from agenttransponder.v1 import events_pb2_grpc
        # If they haven't been generated yet we fall back to a dynamic stub
        # that uses the low-level gRPC API.
        try:
            from agenttransponder.v1 import events_pb2_grpc  # type: ignore[import]
            self._stub = events_pb2_grpc.EventIngestionStub(channel)
            self._use_generated_stub = True
        except ImportError:
            logger.warning(
                "Generated proto stubs not found — falling back to raw gRPC. "
                "Run `task proto` to generate the stubs."
            )
            self._stub = None
            self._use_generated_stub = False

    def ping(self) -> bool:
        """Return True if the server is reachable and authenticated."""
        self._ensure_connected()
        if not self._use_generated_stub or self._stub is None:
            return False
        try:
            from agenttransponder.v1 import events_pb2  # type: ignore[import]
            self._stub.Ping(events_pb2.PingRequest(), timeout=5)
            return True
        except Exception as exc:  # noqa: BLE001
            logger.debug("Ping failed: %s", exc)
            return False

    def send_event(self, event: Event) -> bool:
        """Send a single event.  Returns True on success."""
        self._ensure_connected()
        if not self._use_generated_stub or self._stub is None:
            logger.debug("Stub unavailable; dropping event %s", event.id)
            return False
        try:
            from agenttransponder.v1 import events_pb2  # type: ignore[import]
            proto_event = _event_to_proto(event, events_pb2)
            resp = self._stub.IngestEvent(
                events_pb2.IngestEventRequest(event=proto_event),
                timeout=10,
            )
            if not resp.accepted:
                logger.warning(
                    "Event %s rejected: %s (%s)",
                    event.id, resp.error, resp.rejection_reason,
                )
                return False
            return True
        except Exception as exc:  # noqa: BLE001
            logger.debug("IngestEvent failed: %s", exc)
            return False

    def close(self) -> None:
        if self._channel is not None:
            try:
                self._channel.close()
            except Exception:  # noqa: BLE001
                pass
            self._channel = None
            self._stub = None


def _event_to_proto(event: Event, pb2: object) -> object:
    """Convert an SDK Event to the protobuf Event message."""
    from google.protobuf import timestamp_pb2, struct_pb2  # type: ignore[import]

    ts = timestamp_pb2.Timestamp()
    ts.FromDatetime(event.timestamp)

    kwargs: dict = {
        "id": event.id,
        "session_id": event.session_id,
        "agent_id": event.agent_id,
        "tenant_id": event.tenant_id,
        "type": int(event.type),
        "severity": int(event.severity),
        "timestamp": ts,
        "model": event.model,
        "hmac": event.hmac,
        "labels": event.labels,
    }

    if event.prompt is not None:
        kwargs["prompt"] = pb2.PromptData(
            content=event.prompt.content,
            role=event.prompt.role,
            token_count=event.prompt.token_count,
        )
    if event.response is not None:
        kwargs["response"] = pb2.ResponseData(
            content=event.response.content,
            finish_reason=event.response.finish_reason,
            token_count=event.response.token_count,
        )
    if event.tool_call is not None:
        args_struct = struct_pb2.Struct()
        args_struct.update(event.tool_call.arguments)
        result_struct = struct_pb2.Struct()
        result_struct.update(event.tool_call.result)
        kwargs["tool_call"] = pb2.ToolCallData(
            tool_name=event.tool_call.tool_name,
            arguments=args_struct,
            result=result_struct,
            success=event.tool_call.success,
            error_msg=event.tool_call.error_msg,
            retry_count=event.tool_call.retry_count,
        )
    if event.memory is not None:
        kwargs["memory"] = pb2.MemoryData(
            operation=event.memory.operation,
            key=event.memory.key,
            value=event.memory.value,
        )
    if event.reasoning is not None:
        kwargs["reasoning"] = pb2.ReasoningData(
            step=event.reasoning.step,
            content=event.reasoning.content,
        )
    if event.error is not None:
        kwargs["error"] = pb2.ErrorData(
            code=event.error.code,
            message=event.error.message,
            stacktrace=event.error.stacktrace,
            retryable=event.error.retryable,
        )
    if event.token_usage is not None:
        kwargs["token_usage"] = pb2.TokenUsage(
            prompt_tokens=event.token_usage.prompt_tokens,
            completion_tokens=event.token_usage.completion_tokens,
            total_tokens=event.token_usage.total_tokens,
        )

    return pb2.Event(**kwargs)


# ---------------------------------------------------------------------------
# Background sender with retry / backoff
# ---------------------------------------------------------------------------

class EventSender:
    """Drains the shared event queue and delivers events to the gRPC transport.

    Runs in a daemon thread.  Uses exponential backoff on transient errors.
    """

    # gRPC status codes that are worth retrying
    _RETRYABLE_CODES = frozenset([
        "UNAVAILABLE",
        "RESOURCE_EXHAUSTED",
        "DEADLINE_EXCEEDED",
        "INTERNAL",
    ])

    def __init__(self, cfg: TransponderConfig, event_queue: queue.Queue) -> None:
        self._cfg = cfg
        self._queue = event_queue
        self._transport = GrpcTransport(cfg)
        self._thread = threading.Thread(
            target=self._run,
            name="at-sender",
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self, timeout: float) -> None:
        self._queue.put(_STOP)
        self._thread.join(timeout=timeout)

    def _run(self) -> None:
        while True:
            try:
                item = self._queue.get(timeout=self._cfg.flush_interval_sec)
            except queue.Empty:
                continue

            if item is _STOP:
                # Drain remaining events before exiting
                self._drain()
                self._transport.close()
                return

            assert isinstance(item, Event)
            self._deliver_with_retry(item)

    def _drain(self) -> None:
        """Send all remaining events in the queue (best-effort)."""
        while True:
            try:
                item = self._queue.get_nowait()
            except queue.Empty:
                return
            if item is _STOP:
                return
            if isinstance(item, Event):
                self._deliver_with_retry(item)

    def _deliver_with_retry(self, event: Event) -> None:
        """Attempt to send *event*, retrying with exponential backoff."""
        cfg = self._cfg
        delay = cfg.retry_base_delay_sec
        for attempt in range(cfg.max_retries + 1):
            success = self._transport.send_event(event)
            if success:
                return
            if attempt == cfg.max_retries:
                logger.error(
                    "Dropping event %s after %d attempts", event.id, attempt + 1
                )
                return
            sleep_time = min(delay * (2 ** attempt), cfg.retry_max_delay_sec)
            logger.debug(
                "Retry %d/%d for event %s in %.2fs",
                attempt + 1, cfg.max_retries, event.id, sleep_time,
            )
            time.sleep(sleep_time)
