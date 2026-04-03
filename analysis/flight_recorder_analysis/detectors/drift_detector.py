"""
Goal-drift detector — uses Jaccard token similarity to measure how much
subsequent prompts diverge from the session's initial prompt.

Algorithm
---------
1. Extract all ``prompt`` events in chronological order.
2. Tokenise each prompt's ``content`` field using a simple regex split on
   word-boundary characters (no ML, no external libraries).
3. Treat the *first* prompt as the reference (the agent's original goal).
4. For each subsequent prompt, compute Jaccard similarity against the
   reference set::

       J(A, B) = |A ∩ B| / |A ∪ B|

5. If *every* subsequent prompt falls below ``drift_threshold``, emit a
   single :class:`Detection` for the whole session.  If only *some* prompts
   drift, emit a detection for those specific events (partial drift).

No numpy / scipy — pure Python stdlib only.
"""

from __future__ import annotations

import re
from typing import Sequence

from flight_recorder_analysis.config import DriftDetectorConfig
from flight_recorder_analysis.detectors.base import BaseDetector
from flight_recorder_analysis.models import Detection, DetectionType, Event, Severity

# Matches sequences of Unicode word characters (letters, digits, underscore).
_TOKEN_RE = re.compile(r"\w+", re.UNICODE)


def _tokenise(text: str) -> frozenset[str]:
    """Lower-case word tokens from *text*, returned as a frozenset."""
    return frozenset(t.lower() for t in _TOKEN_RE.findall(text))


def _jaccard(a: frozenset[str], b: frozenset[str]) -> float:
    """Jaccard similarity between two token sets.  Returns 0.0 for empty inputs."""
    if not a and not b:
        return 1.0  # Both empty → identical
    union = a | b
    if not union:
        return 0.0
    return len(a & b) / len(union)


class DriftDetector(BaseDetector):
    """Detects goal drift by comparing prompt similarity over a session."""

    def __init__(self, config: DriftDetectorConfig | None = None) -> None:
        self._cfg = config or DriftDetectorConfig()

    # ------------------------------------------------------------------
    # BaseDetector interface
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "DriftDetector"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def detection_type(self) -> DetectionType:
        return DetectionType.GOAL_DRIFT

    @property
    def description(self) -> str:
        return (
            "Measures token-overlap (Jaccard) similarity between the initial "
            "session prompt and subsequent prompts.  Low similarity signals "
            "goal drift."
        )

    # ------------------------------------------------------------------
    # Detection logic
    # ------------------------------------------------------------------

    def detect(self, events: list[Event]) -> list[Detection]:
        if not events:
            return []

        prompt_events = [
            e for e in events if e.type == "prompt" and e.prompt
        ]
        if len(prompt_events) < self._cfg.min_prompts:
            return []

        # Reference: first prompt in the session.
        reference_tokens = _tokenise(
            prompt_events[0].prompt.get("content", "")  # type: ignore[union-attr]
        )

        drifted: list[tuple[Event, float]] = []
        for e in prompt_events[1:]:
            content = e.prompt.get("content", "")  # type: ignore[union-attr]
            tokens = _tokenise(content)
            sim = _jaccard(reference_tokens, tokens)
            if sim < self._cfg.drift_threshold:
                drifted.append((e, sim))

        if not drifted:
            return []

        drifted_ids = [e.id for e, _ in drifted]
        similarities = [sim for _, sim in drifted]
        avg_sim = sum(similarities) / len(similarities)
        min_sim = min(similarities)

        # Confidence is inversely proportional to average similarity:
        # lower similarity → higher confidence that drift is real.
        confidence = round(min(1.0 - avg_sim + 0.1, 1.0), 2)

        total_subsequent = len(prompt_events) - 1
        drift_fraction = len(drifted) / total_subsequent if total_subsequent else 0.0

        severity = (
            Severity.ERROR
            if drift_fraction >= 0.8
            else Severity.WARNING
        )

        return [
            Detection(
                type=DetectionType.GOAL_DRIFT,
                severity=severity,
                confidence=confidence,
                message=(
                    f"{len(drifted)}/{total_subsequent} subsequent prompts have "
                    f"Jaccard similarity < {self._cfg.drift_threshold} vs. initial "
                    f"prompt (avg={avg_sim:.2f}, min={min_sim:.2f})"
                ),
                event_ids=drifted_ids,
                evidence=(
                    f"drift_threshold={self._cfg.drift_threshold}, "
                    f"avg_similarity={avg_sim:.3f}, "
                    f"min_similarity={min_sim:.3f}, "
                    f"drifted_prompts={len(drifted)}, "
                    f"total_subsequent_prompts={total_subsequent}"
                ),
            )
        ]
