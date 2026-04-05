"""
End-to-end HMAC round-trip test — no gRPC required.

Simulates the full pipeline:
  1. Python creates Event, signs HMAC
  2. Python converts to protobuf
  3. Protobuf is serialized to bytes
  4. Protobuf is deserialized from bytes
  5. Event is reconstructed from protobuf
  6. HMAC is verified on reconstructed event

If this test fails, the proto round-trip is losing or modifying data that
the HMAC was computed over. The assertion message shows exactly which fields
differ.
"""

from __future__ import annotations

from datetime import timezone

import pytest

from agent_transponder.events import Event, EventType, PromptData, Severity
from agent_transponder.hmac import _canonical_json, sign_event, verify_event


def _import_pb2():
    """Import the generated proto stubs, trying both install paths."""
    try:
        from agent_transponder.agenttransponder.v1 import events_pb2

        return events_pb2
    except ImportError:
        pass
    try:
        from agenttransponder.v1 import events_pb2  # type: ignore[import]

        return events_pb2
    except ImportError:
        pytest.skip("Proto stubs not available — run `make proto-python`")


def _event_to_proto(event: Event, pb2):
    """Local copy of _event_to_proto to avoid importing the full client module."""
    from agent_transponder.client import _event_to_proto as _real

    return _real(event, pb2)


def _reconstruct_from_proto(proto_event, pb2) -> Event:
    """Reconstruct an Event from a proto message (mirrors Go's protoToEvent)."""
    restored = Event(
        id=proto_event.id,
        session_id=proto_event.session_id,
        agent_id=proto_event.agent_id,
        tenant_id=proto_event.tenant_id,
        type=EventType(proto_event.type),
        severity=Severity(proto_event.severity),
        model=proto_event.model,
        hmac=proto_event.hmac,
        run_id=proto_event.run_id or None,
        parent_run_id=proto_event.parent_run_id or None,
        tags=list(proto_event.tags) if proto_event.tags else None,
    )

    # Restore timestamp
    if proto_event.HasField("timestamp"):
        restored.timestamp = proto_event.timestamp.ToDatetime(tzinfo=timezone.utc)

    # Restore prompt
    if proto_event.HasField("prompt"):
        restored.prompt = PromptData(
            content=proto_event.prompt.content,
            role=proto_event.prompt.role,
            token_count=proto_event.prompt.token_count,
        )

    return restored


def test_hmac_survives_proto_roundtrip():
    """HMAC must remain valid after proto serialization + deserialization."""
    pb2 = _import_pb2()

    # Step 1: Create and sign
    event = Event(
        id="test-roundtrip",
        session_id="sess-1",
        agent_id="sdk-demo",
        tenant_id="demo",
        type=EventType.PROMPT,
        severity=Severity.INFO,
        model="test-model",
        prompt=PromptData(content="hello", role="user", token_count=1),
        run_id="run-123",
        parent_run_id="parent-456",
        tags=["test", "demo"],
    )
    key = b"demo-hmac-key"
    sign_event(event, key)
    original_canonical = _canonical_json(event).decode()

    # Step 2: Convert to proto
    proto_event = _event_to_proto(event, pb2)

    # Steps 3–4: Serialize and deserialize
    proto_bytes = proto_event.SerializeToString()
    restored_proto = pb2.Event()
    restored_proto.ParseFromString(proto_bytes)

    # Step 5: Reconstruct Event from proto
    restored = _reconstruct_from_proto(restored_proto, pb2)

    # Step 6: Compare canonical JSON and verify HMAC
    restored_canonical = _canonical_json(restored).decode()

    assert original_canonical == restored_canonical, (
        "Canonical JSON mismatch after proto round-trip!\n"
        f"ORIGINAL: {original_canonical}\n"
        f"RESTORED: {restored_canonical}"
    )
    assert verify_event(restored, key), "HMAC verification failed after round-trip"


def test_hmac_survives_roundtrip_minimal_event():
    """Round-trip with a minimal event (no optional fields)."""
    pb2 = _import_pb2()

    event = Event(
        id="test-minimal",
        session_id="sess-2",
        agent_id="agent-x",
        tenant_id="tenant-y",
        type=EventType.RESPONSE,
        severity=Severity.DEBUG,
    )
    key = b"test-key"
    sign_event(event, key)
    original_canonical = _canonical_json(event).decode()

    proto_event = _event_to_proto(event, pb2)
    proto_bytes = proto_event.SerializeToString()
    restored_proto = pb2.Event()
    restored_proto.ParseFromString(proto_bytes)
    restored = _reconstruct_from_proto(restored_proto, pb2)

    restored_canonical = _canonical_json(restored).decode()
    assert original_canonical == restored_canonical, (
        "Canonical JSON mismatch for minimal event!\n"
        f"ORIGINAL: {original_canonical}\n"
        f"RESTORED: {restored_canonical}"
    )
    assert verify_event(restored, key), "HMAC verification failed for minimal event"
