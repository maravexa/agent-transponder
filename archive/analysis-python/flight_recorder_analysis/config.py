"""
Configuration for the Flight Recorder Analysis Engine.

All settings are read from environment variables with an ``AT_`` prefix so
they compose naturally with the rest of the agent-transponder stack.
Settings can also be overridden programmatically (useful in tests).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(
            f"Environment variable {name}={raw!r} must be an integer"
        ) from exc


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ValueError(
            f"Environment variable {name}={raw!r} must be a float"
        ) from exc


# ---------------------------------------------------------------------------
# Per-detector configuration dataclasses
# ---------------------------------------------------------------------------


@dataclass
class LoopDetectorConfig:
    """Configuration for :class:`~detectors.loop_detector.LoopDetector`."""

    # Minimum length of a repeating tool-call subsequence to consider.
    min_sequence_len: int = field(
        default_factory=lambda: _env_int("AT_LOOP_MIN_SEQ_LEN", 2)
    )
    # Minimum number of repetitions before raising a detection.
    min_repetitions: int = field(
        default_factory=lambda: _env_int("AT_LOOP_MIN_REPETITIONS", 3)
    )


@dataclass
class ToolMisuseConfig:
    """Configuration for :class:`~detectors.tool_misuse.ToolMisuseDetector`."""

    # Maximum retries per (tool, canonical-args) pair before flagging.
    max_retries: int = field(default_factory=lambda: _env_int("AT_TOOL_MAX_RETRIES", 5))
    # Fraction of calls to a tool that must fail before flagging the tool.
    min_failure_rate: float = field(
        default_factory=lambda: _env_float("AT_TOOL_MIN_FAILURE_RATE", 0.7)
    )
    # Minimum number of calls before the failure-rate check applies.
    min_calls_for_rate: int = field(
        default_factory=lambda: _env_int("AT_TOOL_MIN_CALLS_FOR_RATE", 3)
    )


@dataclass
class DriftDetectorConfig:
    """Configuration for :class:`~detectors.drift_detector.DriftDetector`."""

    # Jaccard similarity below this threshold triggers a drift detection.
    drift_threshold: float = field(
        default_factory=lambda: _env_float("AT_DRIFT_THRESHOLD", 0.3)
    )
    # Minimum number of prompts in the session before drift is evaluated.
    min_prompts: int = field(
        default_factory=lambda: _env_int("AT_DRIFT_MIN_PROMPTS", 3)
    )


# ---------------------------------------------------------------------------
# Top-level configuration
# ---------------------------------------------------------------------------


@dataclass
class AnalysisConfig:
    """
    Top-level configuration for the analysis engine.

    Instantiate once at startup; inject into detectors and the gRPC server.
    """

    # gRPC listen address (host:port).
    listen_addr: str = field(
        default_factory=lambda: _env("AT_LISTEN_ADDR", "[::]:50052")
    )

    # mTLS material (paths).  Empty string means TLS is disabled (dev only).
    tls_cert: str = field(default_factory=lambda: _env("AT_TLS_CERT", ""))
    tls_key: str = field(default_factory=lambda: _env("AT_TLS_KEY", ""))
    tls_ca: str = field(default_factory=lambda: _env("AT_TLS_CA", ""))

    # Detector sub-configs.
    loop: LoopDetectorConfig = field(default_factory=LoopDetectorConfig)
    tool_misuse: ToolMisuseConfig = field(default_factory=ToolMisuseConfig)
    drift: DriftDetectorConfig = field(default_factory=DriftDetectorConfig)

    @property
    def mtls_enabled(self) -> bool:
        """Return True when all three TLS artefacts are configured."""
        return bool(self.tls_cert and self.tls_key and self.tls_ca)
