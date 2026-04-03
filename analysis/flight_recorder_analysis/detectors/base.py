"""
Abstract base class for all behavioural detectors.

Every detector is stateless between calls: ``detect()`` receives the full
event window and returns zero-or-more :class:`~flight_recorder_analysis.models.Detection`
objects.  The gRPC server orchestrates detector execution and aggregates
results.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from flight_recorder_analysis.models import Detection, DetectionType, Event


class BaseDetector(ABC):
    """
    Contract that every detector must satisfy.

    Implementations should be stateless — all state needed for analysis must
    be derived from the ``events`` argument passed to :meth:`detect`.
    """

    @abstractmethod
    def detect(self, events: list[Event]) -> list[Detection]:
        """
        Analyse *events* and return any detected anomalies.

        Parameters
        ----------
        events:
            Ordered list of telemetry events for a single session, sorted
            ascending by ``timestamp``.

        Returns
        -------
        list[Detection]
            Zero or more detections.  An empty list means the detector found
            nothing noteworthy.
        """

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable detector name (used in ListDetectors responses)."""

    @property
    @abstractmethod
    def version(self) -> str:
        """Semantic version string, e.g. ``"1.0.0"``."""

    @property
    @abstractmethod
    def detection_type(self) -> DetectionType:
        """The :class:`DetectionType` this detector produces."""

    @property
    def description(self) -> str:
        """Optional human-readable description of what this detector looks for."""
        return ""
