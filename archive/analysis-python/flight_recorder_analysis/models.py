"""
Shared domain models for the analysis engine.

These are plain Python dataclasses — no proto dependency.  The gRPC server
layer converts to/from proto messages at the boundary.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class DetectionType(str, Enum):
    """Types of behavioural anomaly the engine can surface."""

    TASK_LOOP = "task_loop"
    TOOL_MISUSE = "tool_misuse"
    GOAL_DRIFT = "goal_drift"
    HALLUCINATION = "hallucination"
    FAILURE_CASCADE = "failure_cascade"
    REWARD_HACKING = "reward_hacking"
    PERSONALITY_DRIFT = "personality_drift"


class EventType(str, Enum):
    """Mirrors EventType in events.proto."""

    PROMPT = "prompt"
    RESPONSE = "response"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    MEMORY_READ = "memory_read"
    MEMORY_WRITE = "memory_write"
    REASONING_STEP = "reasoning_step"
    ERROR = "error"
    RETRY = "retry"
    METADATA = "metadata"


class Severity(str, Enum):
    """Mirrors Severity in events.proto."""

    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Event dataclass
# ---------------------------------------------------------------------------


@dataclass
class Event:
    """
    Canonical telemetry event.

    Content fields (prompt, response, tool_call, memory, reasoning, error) are
    plain dicts so the dataclass has no hard dependency on the proto-generated
    classes.  At most one content field is populated per event, matching the
    proto semantics.
    """

    id: str
    session_id: str
    agent_id: str
    tenant_id: str
    type: str  # EventType value or raw string
    severity: str  # Severity value or raw string
    timestamp: float  # Unix epoch seconds (float for sub-second precision)

    # Content — at most one populated per event
    prompt: dict[str, Any] | None = None
    response: dict[str, Any] | None = None
    # tool_call keys: tool_name, arguments, result, success, error_msg, retry_count
    tool_call: dict[str, Any] | None = None
    memory: dict[str, Any] | None = None
    reasoning: dict[str, Any] | None = None
    error: dict[str, Any] | None = None

    model: str | None = None
    labels: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Detection dataclass
# ---------------------------------------------------------------------------


@dataclass
class Detection:
    """A single behavioural anomaly surfaced by a detector."""

    type: str  # DetectionType value or raw string
    severity: str  # Severity value or raw string
    confidence: float  # 0.0 – 1.0
    message: str
    event_ids: list[str] = field(default_factory=list)
    evidence: str = ""
