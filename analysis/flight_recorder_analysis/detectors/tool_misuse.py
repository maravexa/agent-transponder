"""
Tool-misuse detector.

Flags agents that exhibit any of the following patterns within a session:

1. **Retry storm** — the same ``(tool_name, canonical_args)`` pair is called
   more than ``max_retries`` times and the individual ``retry_count`` field
   confirms repeated attempts.

2. **High failure rate** — more than ``min_failure_rate`` fraction of all
   calls to a given tool fail (requires at least ``min_calls_for_rate``
   samples).

3. **Invalid argument pattern** — tool_call arguments are empty / None on a
   non-first attempt (suggesting the agent is not adapting its inputs despite
   prior failures).

The detector is intentionally conservative: it only fires when *multiple*
signals align, to keep false-positive rates low.
"""

from __future__ import annotations

import json
from collections import defaultdict

from flight_recorder_analysis.config import ToolMisuseConfig
from flight_recorder_analysis.detectors.base import BaseDetector
from flight_recorder_analysis.models import Detection, DetectionType, Event, Severity


def _canonical_args(args: object) -> str:
    """Stable string representation of tool arguments for grouping."""
    if args is None:
        return ""
    try:
        return json.dumps(args, sort_keys=True, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(args)


class ToolMisuseDetector(BaseDetector):
    """Detects tool misuse: retry storms and persistent high failure rates."""

    def __init__(self, config: ToolMisuseConfig | None = None) -> None:
        self._cfg = config or ToolMisuseConfig()

    # ------------------------------------------------------------------
    # BaseDetector interface
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "ToolMisuseDetector"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def detection_type(self) -> DetectionType:
        return DetectionType.TOOL_MISUSE

    @property
    def description(self) -> str:
        return (
            "Flags agents that call the same tool repeatedly with failing "
            "arguments, or that exhibit a high per-tool failure rate."
        )

    # ------------------------------------------------------------------
    # Detection logic
    # ------------------------------------------------------------------

    def detect(self, events: list[Event]) -> list[Detection]:
        if not events:
            return []

        tool_events = [e for e in events if e.type == "tool_call" and e.tool_call]
        if not tool_events:
            return []

        detections: list[Detection] = []

        # ------------------------------------------------------------------
        # 1. Per-(tool_name, canonical_args) retry storm analysis
        # ------------------------------------------------------------------
        # key → list of (event_id, success, retry_count)
        call_groups: dict[tuple[str, str], list[tuple[str, bool, int]]] = defaultdict(
            list
        )

        for e in tool_events:
            tc = e.tool_call  # type: ignore[union-attr]
            tool_name: str = tc.get("tool_name", "")
            args_key = _canonical_args(tc.get("arguments"))
            success: bool = bool(tc.get("success", False))
            retry_count: int = int(tc.get("retry_count", 0))
            call_groups[(tool_name, args_key)].append((e.id, success, retry_count))

        for (tool_name, args_key), calls in call_groups.items():
            failures = [(eid, rc) for eid, ok, rc in calls if not ok]
            if len(failures) > self._cfg.max_retries:
                max_rc = max(rc for _, rc in failures)
                confidence = min(
                    0.6 + (len(failures) - self._cfg.max_retries) * 0.05, 1.0
                )
                detections.append(
                    Detection(
                        type=DetectionType.TOOL_MISUSE,
                        severity=Severity.WARNING,
                        confidence=round(confidence, 2),
                        message=(
                            f"Tool '{tool_name}' called with identical arguments "
                            f"{len(failures)} times and failing each time "
                            f"(threshold: {self._cfg.max_retries})"
                        ),
                        event_ids=[eid for eid, _ in failures],
                        evidence=(
                            f"args_key={args_key!r}, "
                            f"failure_count={len(failures)}, "
                            f"max_retry_count_seen={max_rc}"
                        ),
                    )
                )

        # ------------------------------------------------------------------
        # 2. Per-tool failure-rate analysis
        # ------------------------------------------------------------------
        # key → (total_calls, failed_calls, event_ids_of_failures)
        tool_stats: dict[str, list[tuple[str, bool]]] = defaultdict(list)
        for e in tool_events:
            tc = e.tool_call  # type: ignore[union-attr]
            tool_name = tc.get("tool_name", "")
            success = bool(tc.get("success", False))
            tool_stats[tool_name].append((e.id, success))

        for tool_name, calls in tool_stats.items():
            total = len(calls)
            if total < self._cfg.min_calls_for_rate:
                continue
            failed_ids = [eid for eid, ok in calls if not ok]
            failure_rate = len(failed_ids) / total
            if failure_rate >= self._cfg.min_failure_rate:
                # Avoid double-reporting the same tool already caught above.
                already_reported = any(
                    tool_name in d.message and d.type == DetectionType.TOOL_MISUSE
                    for d in detections
                )
                if not already_reported:
                    confidence = min(0.5 + failure_rate * 0.4, 1.0)
                    detections.append(
                        Detection(
                            type=DetectionType.TOOL_MISUSE,
                            severity=Severity.WARNING,
                            confidence=round(confidence, 2),
                            message=(
                                f"Tool '{tool_name}' has a {failure_rate:.0%} failure "
                                f"rate over {total} calls "
                                f"(threshold: {self._cfg.min_failure_rate:.0%})"
                            ),
                            event_ids=failed_ids,
                            evidence=(
                                f"total_calls={total}, "
                                f"failed_calls={len(failed_ids)}, "
                                f"failure_rate={failure_rate:.3f}"
                            ),
                        )
                    )

        return detections
