"""
Loop detector — flags repeated sequences of tool calls within a session.

Algorithm
---------
1. Extract all ``tool_call`` events from the batch, preserving order.
2. Build a sequence of ``(event_type, tool_name)`` tuples (the *signature
   sequence*).
3. Use a sliding-window search: for every possible subsequence length L
   in [min_sequence_len, len(sequence) // min_repetitions], check whether
   any window of length L repeats ``min_repetitions`` consecutive times.
4. If a repeating block is found, emit one :class:`Detection` describing the
   loop with the event IDs that constitute the repeated subsequence.

Complexity: O(N² / min_repetitions) in the worst case, which is acceptable
for the batch sizes expected in agent telemetry (hundreds of events).
"""

from __future__ import annotations

from flight_recorder_analysis.config import LoopDetectorConfig
from flight_recorder_analysis.detectors.base import BaseDetector
from flight_recorder_analysis.models import Detection, DetectionType, Event, Severity


class LoopDetector(BaseDetector):
    """Detects repeated tool-call sequences (task loops) within a session."""

    def __init__(self, config: LoopDetectorConfig | None = None) -> None:
        self._cfg = config or LoopDetectorConfig()

    # ------------------------------------------------------------------
    # BaseDetector interface
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "LoopDetector"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def detection_type(self) -> DetectionType:
        return DetectionType.TASK_LOOP

    @property
    def description(self) -> str:
        return (
            "Detects repeated sequences of tool calls indicating the agent is "
            "stuck in a task loop."
        )

    # ------------------------------------------------------------------
    # Detection logic
    # ------------------------------------------------------------------

    def detect(self, events: list[Event]) -> list[Detection]:
        if not events:
            return []

        tool_events = [e for e in events if e.type == "tool_call" and e.tool_call]
        if len(tool_events) < self._cfg.min_sequence_len * self._cfg.min_repetitions:
            return []

        # Build the signature sequence: (tool_name,) tuples.
        # We use a tuple so subsequences are hashable.
        sigs = [
            (e.tool_call.get("tool_name", ""),)  # type: ignore[union-attr]
            for e in tool_events
        ]
        ids = [e.id for e in tool_events]
        n = len(sigs)

        detections: list[Detection] = []
        # Track which starting positions have already been reported so we
        # don't emit duplicate / nested detections for the same events.
        reported_positions: set[int] = set()

        max_len = n // self._cfg.min_repetitions
        for seq_len in range(self._cfg.min_sequence_len, max_len + 1):
            i = 0
            while i <= n - seq_len * self._cfg.min_repetitions:
                if i in reported_positions:
                    i += 1
                    continue

                window = tuple(sigs[i : i + seq_len])
                reps = 1
                j = i + seq_len
                while j + seq_len <= n and tuple(sigs[j : j + seq_len]) == window:
                    reps += 1
                    j += seq_len

                if reps >= self._cfg.min_repetitions:
                    # Collect event IDs for the repeated span.
                    span_end = i + seq_len * reps
                    involved_ids = ids[i:span_end]
                    tool_names = [s[0] for s in window]

                    # Confidence scales with extra repetitions beyond minimum.
                    extra = reps - self._cfg.min_repetitions
                    confidence = min(0.5 + extra * 0.1, 1.0)

                    detections.append(
                        Detection(
                            type=DetectionType.TASK_LOOP,
                            severity=Severity.WARNING,
                            confidence=round(confidence, 2),
                            message=(
                                f"Tool-call sequence {tool_names!r} repeated "
                                f"{reps}x (threshold: {self._cfg.min_repetitions})"
                            ),
                            event_ids=involved_ids,
                            evidence=(
                                f"Sequence of length {seq_len} repeated {reps} "
                                f"consecutive times starting at position {i} in "
                                f"the tool-call stream."
                            ),
                        )
                    )
                    # Mark all positions in the detected span as reported.
                    for pos in range(i, span_end):
                        reported_positions.add(pos)
                    i = span_end
                else:
                    i += 1

        return detections
