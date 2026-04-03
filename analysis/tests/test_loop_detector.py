"""
Tests for LoopDetector.

All tests use plain Event dataclasses — no gRPC or proto stubs needed.
"""

from __future__ import annotations

import time

from flight_recorder_analysis.config import LoopDetectorConfig
from flight_recorder_analysis.detectors.loop_detector import LoopDetector
from flight_recorder_analysis.models import DetectionType, Event


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _tool_event(
    event_id: str,
    tool_name: str,
    success: bool = True,
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
            "arguments": {},
            "result": {},
            "success": success,
            "error_msg": "",
            "retry_count": 0,
        },
    )


def _make_repeating_sequence(
    tool_names: list[str],
    repetitions: int,
    start_ts: float = 0.0,
) -> list[Event]:
    """Return a list of tool_call events that repeat *tool_names* exactly *repetitions* times."""
    events: list[Event] = []
    idx = 0
    for rep in range(repetitions):
        for name in tool_names:
            events.append(
                _tool_event(
                    event_id=f"e-{idx}",
                    tool_name=name,
                    ts=start_ts + idx,
                )
            )
            idx += 1
    return events


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------


class TestLoopDetector:
    def setup_method(self) -> None:
        cfg = LoopDetectorConfig(min_sequence_len=2, min_repetitions=3)
        self.detector = LoopDetector(cfg)

    # -- 1. Clear repeating pattern ----------------------------------------

    def test_detects_clear_loop(self) -> None:
        """A sequence [search, write] repeated 4 times should trigger a detection."""
        events = _make_repeating_sequence(["search", "write"], repetitions=4)
        detections = self.detector.detect(events)

        assert len(detections) == 1
        d = detections[0]
        assert d.type == DetectionType.TASK_LOOP
        assert d.confidence > 0.0
        assert "search" in d.message or "write" in d.message
        # All 8 events should be captured in event_ids.
        assert len(d.event_ids) == 8

    def test_detects_loop_at_minimum_threshold(self) -> None:
        """Exactly min_repetitions (3) should still fire."""
        events = _make_repeating_sequence(["fetch", "parse"], repetitions=3)
        detections = self.detector.detect(events)

        assert len(detections) == 1
        assert detections[0].type == DetectionType.TASK_LOOP

    def test_below_threshold_no_detection(self) -> None:
        """Only 2 repetitions (below min_repetitions=3) should NOT fire."""
        events = _make_repeating_sequence(["search", "write"], repetitions=2)
        detections = self.detector.detect(events)

        assert detections == []

    # -- 2. Random / non-repeating events -----------------------------------

    def test_no_loop_in_random_sequence(self) -> None:
        """A set of uniquely-named tools should not trigger any detection."""
        tool_names = [f"tool_{i}" for i in range(10)]
        events = [
            _tool_event(event_id=f"e-{i}", tool_name=tool_names[i], ts=float(i))
            for i in range(10)
        ]
        detections = self.detector.detect(events)
        assert detections == []

    def test_no_loop_when_tools_vary(self) -> None:
        """ABCABD — similar but not identical repetitions — should not fire."""
        seq = ["alpha", "beta", "gamma", "alpha", "beta", "delta"]
        events = [
            _tool_event(event_id=f"e-{i}", tool_name=seq[i], ts=float(i))
            for i in range(len(seq))
        ]
        detections = self.detector.detect(events)
        assert detections == []

    # -- 3. Edge case: empty events list ------------------------------------

    def test_empty_events(self) -> None:
        """An empty event list must return an empty detection list."""
        detections = self.detector.detect([])
        assert detections == []

    # -- 4. Edge case: single event ----------------------------------------

    def test_single_event(self) -> None:
        """A single event cannot form a loop."""
        events = [_tool_event("e-0", "search", ts=0.0)]
        detections = self.detector.detect(events)
        assert detections == []

    # -- 5. Non-tool events are ignored -------------------------------------

    def test_ignores_non_tool_events(self) -> None:
        """prompt / response events interleaved should not confuse the detector."""
        tool_events = _make_repeating_sequence(["read", "write"], repetitions=3)
        # Insert prompt events in between
        prompt_events = [
            Event(
                id=f"p-{i}",
                session_id="sess-1",
                agent_id="agent-1",
                tenant_id="tenant-1",
                type="prompt",
                severity="info",
                timestamp=float(i),
                prompt={"content": f"do something {i}", "role": "user"},
            )
            for i in range(3)
        ]
        mixed = sorted(tool_events + prompt_events, key=lambda e: e.id)
        detections = self.detector.detect(mixed)
        assert len(detections) == 1
        assert detections[0].type == DetectionType.TASK_LOOP

    # -- 6. Confidence increases with more repetitions ----------------------

    def test_confidence_increases_with_repetitions(self) -> None:
        """More repetitions should yield higher confidence."""
        cfg = LoopDetectorConfig(min_sequence_len=1, min_repetitions=3)
        detector = LoopDetector(cfg)

        few_reps = _make_repeating_sequence(["ping"], repetitions=3)
        many_reps = _make_repeating_sequence(["ping"], repetitions=7)

        det_few = detector.detect(few_reps)
        det_many = detector.detect(many_reps)

        assert det_few and det_many
        assert det_many[0].confidence >= det_few[0].confidence
