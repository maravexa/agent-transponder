"""
Event dataclasses matching the proto/agenttransponder/v1/events.proto schema.
No proto imports — these are plain Python dataclasses.
"""

from __future__ import annotations

import time
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# UUIDv7 — time-ordered, stdlib only
# ---------------------------------------------------------------------------


def uuid7() -> str:
    """Generate a UUIDv7 (time-ordered) identifier using only stdlib."""
    ms = int(time.time() * 1000)
    rand = os.urandom(10)
    b = bytearray(16)
    b[0] = (ms >> 40) & 0xFF
    b[1] = (ms >> 32) & 0xFF
    b[2] = (ms >> 24) & 0xFF
    b[3] = (ms >> 16) & 0xFF
    b[4] = (ms >> 8) & 0xFF
    b[5] = ms & 0xFF
    b[6] = 0x70 | (rand[0] & 0x0F)  # version 7
    b[7] = rand[1]
    b[8] = 0x80 | (rand[2] & 0x3F)  # variant
    b[9:] = rand[3:]
    hex_str = b.hex()
    return f"{hex_str[:8]}-{hex_str[8:12]}-{hex_str[12:16]}-{hex_str[16:20]}-{hex_str[20:]}"


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class EventType(IntEnum):
    UNSPECIFIED = 0
    PROMPT = 1
    RESPONSE = 2
    TOOL_CALL = 3
    TOOL_RESULT = 4
    MEMORY_READ = 5
    MEMORY_WRITE = 6
    REASONING_STEP = 7
    ERROR = 8
    RETRY = 9
    METADATA = 10


class Severity(IntEnum):
    UNSPECIFIED = 0
    DEBUG = 1
    INFO = 2
    WARNING = 3
    ERROR = 4
    CRITICAL = 5


# String representations matching Go's EventType and Severity string constants.
# These must match exactly what Go's json.Marshal produces for the string types.
_EVENT_TYPE_STR: Dict[EventType, str] = {
    EventType.UNSPECIFIED: "unspecified",
    EventType.PROMPT: "prompt",
    EventType.RESPONSE: "response",
    EventType.TOOL_CALL: "tool_call",
    EventType.TOOL_RESULT: "tool_result",
    EventType.MEMORY_READ: "memory_read",
    EventType.MEMORY_WRITE: "memory_write",
    EventType.REASONING_STEP: "reasoning_step",
    EventType.ERROR: "error",
    EventType.RETRY: "retry",
    EventType.METADATA: "metadata",
}

_SEVERITY_STR: Dict[Severity, str] = {
    Severity.UNSPECIFIED: "unspecified",
    Severity.DEBUG: "debug",
    Severity.INFO: "info",
    Severity.WARNING: "warning",
    Severity.ERROR: "error",
    Severity.CRITICAL: "critical",
}

# Go zero time — used when received_at is None/unset
_GO_ZERO_TIME = "0001-01-01T00:00:00Z"


def _fmt_ts(dt: Optional[datetime]) -> str:
    """Format a datetime as RFC3339 with Z suffix, matching Go's time.Time.MarshalJSON.

    Returns Go's zero time string when dt is None.
    """
    if dt is None:
        return _GO_ZERO_TIME
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    s = dt.isoformat()
    # Python uses +00:00 for UTC; Go uses Z
    if s.endswith("+00:00"):
        s = s[:-6] + "Z"
    # Strip trailing zeros from fractional seconds to match Go time.MarshalJSON
    if "." in s and s.endswith("Z"):
        s = s[:-1].rstrip("0") + "Z"
    return s


# ---------------------------------------------------------------------------
# Payload dataclasses
# ---------------------------------------------------------------------------


@dataclass
class PromptData:
    content: str = ""
    role: str = ""
    token_count: int = 0


@dataclass
class ResponseData:
    content: str = ""
    finish_reason: str = ""
    token_count: int = 0


@dataclass
class ToolCallData:
    tool_name: str = ""
    arguments: Dict[str, Any] = field(default_factory=dict)
    result: Dict[str, Any] = field(default_factory=dict)
    success: bool = False
    error_msg: str = ""
    retry_count: int = 0


@dataclass
class MemoryData:
    operation: str = ""
    key: str = ""
    value: str = ""


@dataclass
class ReasoningData:
    step: int = 0
    content: str = ""


@dataclass
class ErrorData:
    code: str = ""
    message: str = ""
    stacktrace: str = ""
    retryable: bool = False


@dataclass
class TokenUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


# ---------------------------------------------------------------------------
# Nested struct serialisation helpers (omitempty parity with Go json tags)
# ---------------------------------------------------------------------------


def _ser_prompt(p: PromptData) -> dict:
    """Serialise PromptData matching Go struct json tags with omitempty."""
    d: dict = {"content": p.content}
    if p.role:  # omitempty
        d["role"] = p.role
    if p.token_count:  # omitempty
        d["token_count"] = p.token_count
    return d


def _ser_response(r: ResponseData) -> dict:
    """Serialise ResponseData matching Go struct json tags with omitempty."""
    d: dict = {"content": r.content}
    if r.finish_reason:  # omitempty
        d["finish_reason"] = r.finish_reason
    if r.token_count:  # omitempty
        d["token_count"] = r.token_count
    return d


def _ser_tool_call(tc: ToolCallData) -> dict:
    """Serialise ToolCallData matching Go struct json tags with omitempty."""
    d: dict = {"tool_name": tc.tool_name, "success": tc.success}
    if tc.error_msg:  # omitempty
        d["error_msg"] = tc.error_msg
    if tc.arguments:  # omitempty — omit when None or empty dict
        d["arguments"] = tc.arguments
    if tc.result:  # omitempty — omit when None or empty dict
        d["result"] = tc.result
    if tc.retry_count:  # omitempty
        d["retry_count"] = tc.retry_count
    return d


def _ser_memory(m: MemoryData) -> dict:
    """Serialise MemoryData matching Go struct json tags with omitempty."""
    d: dict = {"operation": m.operation, "key": m.key}
    if m.value:  # omitempty
        d["value"] = m.value
    return d


def _ser_reasoning(r: ReasoningData) -> dict:
    """Serialise ReasoningData matching Go struct json tags (no omitempty)."""
    return {"content": r.content, "step": r.step}


def _ser_error(e: ErrorData) -> dict:
    """Serialise ErrorData matching Go struct json tags with omitempty."""
    d: dict = {"message": e.message, "retryable": e.retryable}
    if e.code:  # omitempty
        d["code"] = e.code
    if e.stacktrace:  # omitempty
        d["stacktrace"] = e.stacktrace
    return d


def _ser_token_usage(tu: TokenUsage) -> dict:
    """Serialise TokenUsage matching Go struct json tags (no omitempty)."""
    return {
        "prompt_tokens": tu.prompt_tokens,
        "completion_tokens": tu.completion_tokens,
        "total_tokens": tu.total_tokens,
    }


# ---------------------------------------------------------------------------
# Canonical Event
# ---------------------------------------------------------------------------


@dataclass
class Event:
    """Canonical telemetry event.  Mirrors the proto Event message."""

    id: str = field(default_factory=uuid7)
    session_id: str = ""
    agent_id: str = ""
    tenant_id: str = ""

    type: EventType = EventType.UNSPECIFIED
    severity: Severity = Severity.INFO

    timestamp: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))
    # received_at is set by the ingester; SDK leaves it as None (serialises to Go zero time)
    received_at: Optional[datetime] = None

    duration_ms: float = 0.0

    # Payload — at most one should be set per event
    prompt: Optional[PromptData] = None
    response: Optional[ResponseData] = None
    tool_call: Optional[ToolCallData] = None
    memory: Optional[MemoryData] = None
    reasoning: Optional[ReasoningData] = None
    error: Optional[ErrorData] = None

    model: str = ""
    token_usage: Optional[TokenUsage] = None
    labels: Dict[str, str] = field(default_factory=dict)

    # Causal attribution — populated by framework integrations
    run_id: Optional[str] = None
    parent_run_id: Optional[str] = None
    tags: Optional[List[str]] = None

    # Integrity — computed after construction, before transmission
    hmac: str = ""

    # Redaction tracking — set by ingestion after redaction
    redacted_fields: Optional[List[str]] = None

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    def to_dict(self, include_hmac: bool = True) -> dict:
        """Return a JSON-serialisable dict matching Go's json.Marshal output.

        Field presence and names match the Go Event struct json tags exactly,
        including omitempty semantics, so that HMAC-SHA256 signatures computed
        on both sides are identical.
        """
        # Fields with no omitempty in Go — always included
        d: dict = {
            "id": self.id,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "tenant_id": self.tenant_id,
            "type": _EVENT_TYPE_STR[self.type],
            "severity": _SEVERITY_STR[self.severity],
            "timestamp": _fmt_ts(self.timestamp),
            # received_at has omitempty in Go but time.Time structs are never
            # considered empty by encoding/json, so it is always present.
            "received_at": _fmt_ts(self.received_at),
        }

        # Payload fields — omitempty pointers, omit when None
        if self.prompt is not None:
            d["prompt"] = _ser_prompt(self.prompt)
        if self.response is not None:
            d["response"] = _ser_response(self.response)
        if self.tool_call is not None:
            d["tool_call"] = _ser_tool_call(self.tool_call)
        if self.memory is not None:
            d["memory"] = _ser_memory(self.memory)
        if self.reasoning is not None:
            d["reasoning"] = _ser_reasoning(self.reasoning)
        if self.error is not None:
            d["error"] = _ser_error(self.error)

        # Model metadata — omitempty strings/pointers
        if self.model:  # omitempty
            d["model"] = self.model
        if self.token_usage is not None:
            d["token_usage"] = _ser_token_usage(self.token_usage)
        if self.labels:  # omitempty map
            d["labels"] = self.labels

        # Causal attribution — omitempty strings/slices
        if self.run_id:
            d["run_id"] = self.run_id
        if self.parent_run_id:
            d["parent_run_id"] = self.parent_run_id
        if self.tags:
            d["tags"] = self.tags

        # Integrity — always included (no omitempty in Go)
        if include_hmac:
            d["hmac"] = self.hmac

        # Redaction tracking — omitempty slice
        if self.redacted_fields:
            d["redacted_fields"] = self.redacted_fields

        # Duration — Go uses time.Duration (nanoseconds, int64) with omitempty.
        # Convert duration_ms (float milliseconds) → nanoseconds; omit when zero.
        duration_ns = int(self.duration_ms * 1_000_000)
        if duration_ns:
            d["duration"] = duration_ns

        return d
