"""
Detector sub-package.

All detectors implement :class:`BaseDetector` and work with plain Python
:class:`~flight_recorder_analysis.models.Event` dataclasses — no gRPC or
proto dependency.
"""

from flight_recorder_analysis.detectors.base import BaseDetector
from flight_recorder_analysis.detectors.drift_detector import DriftDetector
from flight_recorder_analysis.detectors.loop_detector import LoopDetector
from flight_recorder_analysis.detectors.tool_misuse import ToolMisuseDetector

__all__ = [
    "BaseDetector",
    "DriftDetector",
    "LoopDetector",
    "ToolMisuseDetector",
]
