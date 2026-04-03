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
from typing import Any, Dict, Optional


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

    # Integrity — computed after construction, before transmission
    hmac: str = ""

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    def to_dict(self, include_hmac: bool = True) -> dict:
        """Return a JSON-serialisable dict representation."""

        def _dataclass_or_none(obj: Any) -> Optional[dict]:
            if obj is None:
                return None
            # Convert nested dataclass fields
            result: dict = {}
            for f_name, f_val in obj.__dict__.items():
                if isinstance(f_val, (dict, list)):
                    result[f_name] = f_val
                else:
                    result[f_name] = f_val
            return result

        d: dict = {
            "id": self.id,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "tenant_id": self.tenant_id,
            "type": int(self.type),
            "severity": int(self.severity),
            "timestamp": self.timestamp.isoformat(),
            "duration_ms": self.duration_ms,
            "model": self.model,
            "labels": self.labels,
        }

        if self.prompt is not None:
            d["prompt"] = _dataclass_or_none(self.prompt)
        if self.response is not None:
            d["response"] = _dataclass_or_none(self.response)
        if self.tool_call is not None:
            d["tool_call"] = _dataclass_or_none(self.tool_call)
        if self.memory is not None:
            d["memory"] = _dataclass_or_none(self.memory)
        if self.reasoning is not None:
            d["reasoning"] = _dataclass_or_none(self.reasoning)
        if self.error is not None:
            d["error"] = _dataclass_or_none(self.error)
        if self.token_usage is not None:
            d["token_usage"] = _dataclass_or_none(self.token_usage)

        if include_hmac:
            d["hmac"] = self.hmac

        return d
