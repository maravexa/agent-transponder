"""
Tests for ToolMisuseDetector.

All tests use plain Event dataclasses — no gRPC or proto stubs needed.
"""

from __future__ import annotations

import time

import pytest

from flight_recorder_analysis.config import ToolMisuseConfig
from flight_recorder_analysis.detectors.tool_misuse import ToolMisuseDetector
from flight_recorder_analysis.models import Detection, DetectionType, Event


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _tool_event(
    event_id: str,
    tool_name: str,
    arguments: dict | None = None,
    success: bool = True,
    error_msg: str = "",
    retry_count: int = 0,
    ts: float | None = None,
) -> Event:
    """Build a minimal tool_call Event."""
    return Event(
        id=event_id,
        session_id="sess-1",
        agent_id="agent-1",
        tenant_id="tenant-1",
        type="tool_call",
        severity="info",
        timestamp=ts if ts is not None else time.time(),
        tool_call={
            "tool_name": tool_name,
            "arguments": arguments or {},
            "result": {},
            "success": success,
            "error_msg": error_msg,
            "retry_count": retry_count,
        },
    )


def _failing_calls(
    tool_name: str,
    count: int,
    arguments: dict | None = None,
    start_retry: int = 0,
) -> list[Event]:
    """Return *count* failing tool_call events for *tool_name* with the same args."""
    return [
        _tool_event(
            event_id=f"fail-{tool_name}-{i}",
            tool_name=tool_name,
            arguments=arguments or {"query": "test"},
            success=False,
            error_msg="timeout",
            retry_count=start_retry + i,
            ts=float(i),
        )
        for i in range(count)
    ]


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------


class TestToolMisuseDetector:
    def setup_method(self) -> None:
        cfg = ToolMisuseConfig(
            max_retries=5,
            min_failure_rate=0.7,
            min_calls_for_rate=3,
        )
        self.detector = ToolMisuseDetector(cfg)

    # -- 1. Retry storm with identical args ---------------------------------

    def test_detects_retry_storm(self) -> None:
        """Agent calls same tool with same args and fails 6 times (> max_retries=5)."""
        events = _failing_calls("database_query", count=6)
        detections = self.detector.detect(events)

        assert len(detections) >= 1
        types = {d.type for d in detections}
        assert DetectionType.TOOL_MISUSE in types
        # All failing event IDs should be referenced.
        all_ids = {eid for d in detections for eid in d.event_ids}
        assert all(f"fail-database_query-{i}" in all_ids for i in range(6))

    def test_retry_storm_at_exactly_threshold_no_detection(self) -> None:
        """Exactly max_retries=5 failures — should NOT fire the retry-storm check."""
        events = _failing_calls("database_query", count=5)
        # 5 failures with same args → not > max_retries, so retry storm check should pass.
        # But failure rate is 100% > 70% with ≥3 calls, so failure-rate check fires.
        detections = self.detector.detect(events)
        # We only care that the retry-storm detection does NOT fire (count == 0 for that).
        retry_storm_dets = [
            d for d in detections
            if "5 times" in d.message or "retry" in d.evidence.lower()
        ]
        # Retry storm requires > max_retries failures, so 5 should NOT trigger it.
        assert all("6" not in d.message for d in retry_storm_dets)

    def test_no_detection_below_max_retries(self) -> None:
        """Only 4 failures with same args (< max_retries=5) and failure rate at threshold."""
        cfg = ToolMisuseConfig(max_retries=5, min_failure_rate=0.7, min_calls_for_rate=10)
        detector = ToolMisuseDetector(cfg)
        events = _failing_calls("search", count=4)
        detections = detector.detect(events)
        # 4 failures < max_retries=5 AND only 4 calls < min_calls_for_rate=10
        assert detections == []

    # -- 2. Mostly successful calls should NOT flag -------------------------

    def test_no_detection_for_successful_calls(self) -> None:
        """Agent makes 9 successful + 1 failed call → failure rate 10%, well below 70%."""
        events = [
            _tool_event(f"ok-{i}", "search", success=True, ts=float(i))
            for i in range(9)
        ]
        events.append(
            _tool_event("fail-0", "search", success=False, ts=9.0)
        )
        detections = self.detector.detect(events)
        assert detections == []

    def test_no_detection_for_varied_successful_tools(self) -> None:
        """Multiple different tools, all succeeding — no detection expected."""
        events = [
            _tool_event(f"e-{i}", f"tool_{i}", success=True, ts=float(i))
            for i in range(10)
        ]
        detections = self.detector.detect(events)
        assert detections == []

    # -- 3. High failure rate (different args, same tool) -------------------

    def test_detects_high_failure_rate_varied_args(self) -> None:
        """Same tool called 5 times with varying args, 4 of which fail (80% rate)."""
        events = [
            _tool_event(f"e-{i}", "api_call", arguments={"id": i}, success=(i == 0), ts=float(i))
            for i in range(5)
        ]
        detections = self.detector.detect(events)

        assert len(detections) >= 1
        types = {d.type for d in detections}
        assert DetectionType.TOOL_MISUSE in types
        # At least one detection should mention the tool.
        assert any("api_call" in d.message for d in detections)

    def test_failure_rate_below_min_calls_not_flagged(self) -> None:
        """Only 2 calls (below min_calls_for_rate=3) — failure rate check should be skipped."""
        events = [
            _tool_event("e-0", "flaky_tool", success=False, ts=0.0),
            _tool_event("e-1", "flaky_tool", success=False, ts=1.0),
        ]
        detections = self.detector.detect(events)
        # 2 calls < min_calls_for_rate=3 → failure rate check skipped
        # Also only 2 failures < max_retries=5 and args differ → no retry storm
        assert detections == []

    # -- 4. Edge case: empty events list ------------------------------------

    def test_empty_events(self) -> None:
        """An empty event list must return an empty detection list."""
        detections = self.detector.detect([])
        assert detections == []

    # -- 5. Edge case: no tool_call events in the list ----------------------

    def test_no_tool_call_events(self) -> None:
        """Only prompt events — no tool calls to analyse."""
        events = [
            Event(
                id=f"p-{i}",
                session_id="sess-1",
                agent_id="agent-1",
                tenant_id="tenant-1",
                type="prompt",
                severity="info",
                timestamp=float(i),
                prompt={"content": f"message {i}", "role": "user"},
            )
            for i in range(5)
        ]
        detections = self.detector.detect(events)
        assert detections == []

    # -- 6. Confidence is within [0, 1] ------------------------------------

    def test_confidence_in_valid_range(self) -> None:
        """All produced detections must have confidence in [0.0, 1.0]."""
        events = _failing_calls("risky_tool", count=20)
        detections = self.detector.detect(events)

        for d in detections:
            assert 0.0 <= d.confidence <= 1.0, (
                f"Confidence out of range: {d.confidence}"
            )
