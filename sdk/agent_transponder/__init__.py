"""
Agent Transponder SDK — public API.

Usage::

    from agent_transponder import Transponder

    tp = Transponder(
        endpoint="localhost:8443",
        ca_cert="/path/to/ca.pem",
        client_cert="/path/to/client.pem",
        client_key="/path/to/client-key.pem",
        hmac_key=b"shared-secret",
        agent_id="my-agent",
        tenant_id="my-team",
    )

    with tp.session() as session:
        session.record_prompt("What is the weather?", role="user", model="gpt-4")
        session.record_response("The weather is sunny.", finish_reason="stop", tokens=12)
        session.record_tool_call(
            "weather_api", args={"city": "NYC"}, result={"temp": 72}, success=True
        )
        session.record_error("timeout", message="API call timed out", retryable=True)
"""
from __future__ import annotations

import logging
import queue
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Generator, Optional

from .config import TransponderConfig
from .events import (
    Event,
    EventType,
    Severity,
    ErrorData,
    MemoryData,
    PromptData,
    ReasoningData,
    ResponseData,
    ToolCallData,
    TokenUsage,
    uuid7,
)
from .hmac import sign_event

__all__ = ["Transponder", "Event", "configure"]

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Session — groups related events and submits them to the Transponder queue
# ---------------------------------------------------------------------------

class Session:
    """Context manager that groups events under a shared session ID.

    Obtain via :py:meth:`Transponder.session`.
    """

    def __init__(self, transponder: "Transponder", session_id: Optional[str] = None) -> None:
        self._tp = transponder
        self._session_id = session_id or uuid7()

    @property
    def session_id(self) -> str:
        return self._session_id

    # ------------------------------------------------------------------
    # Context manager protocol
    # ------------------------------------------------------------------

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *args: Any) -> None:
        self._tp.flush()

    # ------------------------------------------------------------------
    # Recording helpers
    # ------------------------------------------------------------------

    def _submit(self, event: Event) -> None:
        event.session_id = self._session_id
        self._tp._enqueue(event)

    def record_prompt(
        self,
        content: str,
        *,
        role: str = "user",
        model: str = "",
        token_count: int = 0,
        severity: Severity = Severity.INFO,
        labels: Optional[Dict[str, str]] = None,
    ) -> Event:
        """Record a prompt event."""
        event = Event(
            agent_id=self._tp._cfg.agent_id,
            tenant_id=self._tp._cfg.tenant_id,
            type=EventType.PROMPT,
            severity=severity,
            model=model,
            prompt=PromptData(content=content, role=role, token_count=token_count),
            labels=labels or {},
        )
        self._submit(event)
        return event

    def record_response(
        self,
        content: str,
        *,
        finish_reason: str = "",
        tokens: int = 0,
        model: str = "",
        severity: Severity = Severity.INFO,
        labels: Optional[Dict[str, str]] = None,
    ) -> Event:
        """Record a model response event."""
        event = Event(
            agent_id=self._tp._cfg.agent_id,
            tenant_id=self._tp._cfg.tenant_id,
            type=EventType.RESPONSE,
            severity=severity,
            model=model,
            response=ResponseData(
                content=content,
                finish_reason=finish_reason,
                token_count=tokens,
            ),
            labels=labels or {},
        )
        self._submit(event)
        return event

    def record_tool_call(
        self,
        tool_name: str,
        *,
        args: Optional[Dict[str, Any]] = None,
        result: Optional[Dict[str, Any]] = None,
        success: bool = True,
        error_msg: str = "",
        retry_count: int = 0,
        severity: Severity = Severity.INFO,
        labels: Optional[Dict[str, str]] = None,
    ) -> Event:
        """Record a tool call event."""
        event = Event(
            agent_id=self._tp._cfg.agent_id,
            tenant_id=self._tp._cfg.tenant_id,
            type=EventType.TOOL_CALL,
            severity=severity,
            tool_call=ToolCallData(
                tool_name=tool_name,
                arguments=args or {},
                result=result or {},
                success=success,
                error_msg=error_msg,
                retry_count=retry_count,
            ),
            labels=labels or {},
        )
        self._submit(event)
        return event

    def record_error(
        self,
        code: str,
        *,
        message: str = "",
        stacktrace: str = "",
        retryable: bool = False,
        severity: Severity = Severity.ERROR,
        labels: Optional[Dict[str, str]] = None,
    ) -> Event:
        """Record an error event."""
        event = Event(
            agent_id=self._tp._cfg.agent_id,
            tenant_id=self._tp._cfg.tenant_id,
            type=EventType.ERROR,
            severity=severity,
            error=ErrorData(
                code=code,
                message=message,
                stacktrace=stacktrace,
                retryable=retryable,
            ),
            labels=labels or {},
        )
        self._submit(event)
        return event

    def record_reasoning(
        self,
        content: str,
        *,
        step: int = 0,
        severity: Severity = Severity.DEBUG,
        labels: Optional[Dict[str, str]] = None,
    ) -> Event:
        """Record a reasoning-step event."""
        event = Event(
            agent_id=self._tp._cfg.agent_id,
            tenant_id=self._tp._cfg.tenant_id,
            type=EventType.REASONING_STEP,
            severity=severity,
            reasoning=ReasoningData(step=step, content=content),
            labels=labels or {},
        )
        self._submit(event)
        return event

    def record_memory(
        self,
        operation: str,
        key: str,
        value: str = "",
        *,
        severity: Severity = Severity.DEBUG,
        labels: Optional[Dict[str, str]] = None,
    ) -> Event:
        """Record a memory read/write event."""
        etype = (
            EventType.MEMORY_WRITE
            if operation.lower() in ("write", "set", "store")
            else EventType.MEMORY_READ
        )
        event = Event(
            agent_id=self._tp._cfg.agent_id,
            tenant_id=self._tp._cfg.tenant_id,
            type=etype,
            severity=severity,
            memory=MemoryData(operation=operation, key=key, value=value),
            labels=labels or {},
        )
        self._submit(event)
        return event


# ---------------------------------------------------------------------------
# Transponder — main entry point
# ---------------------------------------------------------------------------

class Transponder:
    """Agent Transponder SDK client.

    Thread-safe.  Events are buffered in an in-process queue and delivered
    asynchronously by a background thread.

    Parameters mirror :class:`~agent_transponder.config.TransponderConfig`.
    """

    def __init__(
        self,
        *,
        endpoint: str = "localhost:8443",
        ca_cert: Optional[str] = None,
        client_cert: Optional[str] = None,
        client_key: Optional[str] = None,
        hmac_key: bytes = b"",
        agent_id: str = "",
        tenant_id: str = "",
        queue_maxsize: int = 10_000,
        flush_interval_sec: float = 1.0,
        max_retries: int = 5,
    ) -> None:
        self._cfg = TransponderConfig(
            endpoint=endpoint,
            ca_cert=ca_cert,
            client_cert=client_cert,
            client_key=client_key,
            hmac_key=hmac_key,
            agent_id=agent_id,
            tenant_id=tenant_id,
            queue_maxsize=queue_maxsize,
            flush_interval_sec=flush_interval_sec,
            max_retries=max_retries,
        )
        self._queue: queue.Queue[Any] = queue.Queue(maxsize=queue_maxsize)
        self._lock = threading.Lock()
        self._closed = False
        self._sender: Optional[Any] = None
        self._start_sender()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _start_sender(self) -> None:
        """Start the background sender thread (lazy import to avoid grpc dep in tests)."""
        try:
            from .client import EventSender
            self._sender = EventSender(self._cfg, self._queue)
            self._sender.start()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not start background sender: %s", exc)

    def _enqueue(self, event: Event) -> None:
        """Sign and enqueue an event.  Non-blocking — drops if queue is full."""
        if self._cfg.hmac_key:
            sign_event(event, self._cfg.hmac_key)
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            logger.warning("Event queue full; dropping event %s", event.id)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def session(self, session_id: Optional[str] = None) -> Session:
        """Return a new :class:`Session` context manager."""
        return Session(self, session_id=session_id)

    def flush(self, timeout: float = 5.0) -> None:
        """Block until the queue is empty or *timeout* seconds elapse."""
        try:
            # join() on a Queue is not available in Python — poll instead
            deadline = datetime.now(tz=timezone.utc).timestamp() + timeout
            while not self._queue.empty():
                remaining = deadline - datetime.now(tz=timezone.utc).timestamp()
                if remaining <= 0:
                    break
                import time
                time.sleep(0.05)
        except Exception:  # noqa: BLE001
            pass

    def close(self) -> None:
        """Flush pending events and shut down the background sender."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
        if self._sender is not None:
            self._sender.stop(timeout=self._cfg.shutdown_timeout_sec)

    def __enter__(self) -> "Transponder":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Module-level configure() convenience helper
# ---------------------------------------------------------------------------

_default_transponder: Optional[Transponder] = None
_default_lock = threading.Lock()


def configure(
    *,
    endpoint: str = "localhost:8443",
    ca_cert: Optional[str] = None,
    client_cert: Optional[str] = None,
    client_key: Optional[str] = None,
    hmac_key: bytes = b"",
    agent_id: str = "",
    tenant_id: str = "",
    **kwargs: Any,
) -> Transponder:
    """Create (or replace) the module-level default :class:`Transponder`.

    Useful for applications that want a single global instance::

        from agent_transponder import configure
        configure(endpoint="...", hmac_key=b"...", agent_id="my-agent")
    """
    global _default_transponder
    with _default_lock:
        if _default_transponder is not None:
            _default_transponder.close()
        _default_transponder = Transponder(
            endpoint=endpoint,
            ca_cert=ca_cert,
            client_cert=client_cert,
            client_key=client_key,
            hmac_key=hmac_key,
            agent_id=agent_id,
            tenant_id=tenant_id,
            **kwargs,
        )
    return _default_transponder
