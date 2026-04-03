"""
Agent Transponder — Flight Recorder Analysis Engine.

Provides behaviour detectors (loop, tool-misuse, goal-drift) that run over
batches of agent telemetry events.  The gRPC server layer is optional: all
detector logic works with plain Python dataclasses and has no hard dependency
on generated proto stubs or a running gRPC server.
"""

from flight_recorder_analysis.models import Detection, DetectionType, Event

__all__ = ["Detection", "DetectionType", "Event"]
__version__ = "0.1.0"
