"""
Unit tests for agent_transponder.events — no gRPC required.
"""

from __future__ import annotations

import re
import time
from datetime import datetime

from agent_transponder.events import (
    ErrorData,
    Event,
    EventType,
    MemoryData,
    PromptData,
    ReasoningData,
    ResponseData,
    Severity,
    ToolCallData,
    TokenUsage,
    uuid7,
)


# ---------------------------------------------------------------------------
# UUIDv7 tests
# ---------------------------------------------------------------------------

UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


def test_uuid7_format():
    uid = uuid7()
    assert UUID_RE.match(uid), f"UUIDv7 did not match expected pattern: {uid!r}"


def test_uuid7_version_bits():
    uid = uuid7()
    # 13th hex character (index 14 with dashes removed or position in the third group)
    # The format is xxxxxxxx-xxxx-7xxx-xxxx-xxxxxxxxxxxx
    third_group = uid.split("-")[2]
    assert third_group.startswith("7"), f"Version nibble is not 7: {third_group!r}"


def test_uuid7_variant_bits():
    uid = uuid7()
    # The first character of the 4th group must be 8, 9, a, or b
    fourth_group = uid.split("-")[3]
    assert fourth_group[0] in "89ab", (
        f"Variant bits not set correctly: {fourth_group!r}"
    )


def test_uuid7_unique():
    ids = {uuid7() for _ in range(1000)}
    assert len(ids) == 1000, "UUIDv7 produced duplicate IDs"


def test_uuid7_time_ordered():
    """UUIDv7 IDs generated sequentially should be lexicographically ordered."""
    ids = []
    for _ in range(20):
        ids.append(uuid7())
        # Small sleep to ensure distinct millisecond timestamps
        time.sleep(0.002)
    assert ids == sorted(ids), "UUIDv7 IDs are not time-ordered"


# ---------------------------------------------------------------------------
# Event construction tests
# ---------------------------------------------------------------------------


def test_event_defaults():
    event = Event()
    assert event.id, "Event.id should be auto-generated"
    assert UUID_RE.match(event.id), "Event.id should be a valid UUIDv7"
    assert event.session_id == ""
    assert event.agent_id == ""
    assert event.tenant_id == ""
    assert event.type == EventType.UNSPECIFIED
    assert event.severity == Severity.INFO
    assert isinstance(event.timestamp, datetime)
    assert event.timestamp.tzinfo is not None, "timestamp must be timezone-aware"
    assert event.hmac == ""


def test_event_prompt():
    event = Event(
        agent_id="my-agent",
        tenant_id="my-team",
        type=EventType.PROMPT,
        prompt=PromptData(content="Hello", role="user", token_count=5),
    )
    assert event.type == EventType.PROMPT
    assert event.prompt is not None
    assert event.prompt.content == "Hello"
    assert event.prompt.role == "user"
    assert event.prompt.token_count == 5
    assert event.response is None


def test_event_response():
    event = Event(
        type=EventType.RESPONSE,
        response=ResponseData(content="Hi there", finish_reason="stop", token_count=3),
    )
    assert event.response is not None
    assert event.response.finish_reason == "stop"


def test_event_tool_call():
    event = Event(
        type=EventType.TOOL_CALL,
        tool_call=ToolCallData(
            tool_name="search",
            arguments={"query": "weather"},
            result={"temp": 72},
            success=True,
            retry_count=0,
        ),
    )
    assert event.tool_call is not None
    assert event.tool_call.tool_name == "search"
    assert event.tool_call.arguments == {"query": "weather"}
    assert event.tool_call.success is True


def test_event_error():
    event = Event(
        type=EventType.ERROR,
        severity=Severity.ERROR,
        error=ErrorData(
            code="timeout",
            message="Connection timed out",
            retryable=True,
        ),
    )
    assert event.error is not None
    assert event.error.code == "timeout"
    assert event.error.retryable is True


def test_event_memory():
    event = Event(
        type=EventType.MEMORY_WRITE,
        memory=MemoryData(operation="write", key="ctx", value="some context"),
    )
    assert event.memory is not None
    assert event.memory.key == "ctx"


def test_event_reasoning():
    event = Event(
        type=EventType.REASONING_STEP,
        reasoning=ReasoningData(step=1, content="First, I will..."),
    )
    assert event.reasoning is not None
    assert event.reasoning.step == 1


def test_event_token_usage():
    event = Event(
        token_usage=TokenUsage(prompt_tokens=10, completion_tokens=5, total_tokens=15),
    )
    assert event.token_usage is not None
    assert event.token_usage.total_tokens == 15


def test_event_labels():
    event = Event(labels={"env": "prod", "region": "us-east-1"})
    assert event.labels["env"] == "prod"


# ---------------------------------------------------------------------------
# Event serialisation tests
# ---------------------------------------------------------------------------


def test_to_dict_basic_fields():
    event = Event(
        agent_id="agent-1",
        tenant_id="team-a",
        type=EventType.PROMPT,
        severity=Severity.DEBUG,
        model="gpt-4",
        prompt=PromptData(content="Test", role="system"),
    )
    d = event.to_dict()
    assert d["agent_id"] == "agent-1"
    assert d["tenant_id"] == "team-a"
    assert d["type"] == int(EventType.PROMPT)
    assert d["severity"] == int(Severity.DEBUG)
    assert d["model"] == "gpt-4"
    assert "prompt" in d
    assert d["prompt"]["content"] == "Test"


def test_to_dict_excludes_hmac():
    event = Event(agent_id="a")
    event.hmac = "somedigest"
    d = event.to_dict(include_hmac=False)
    assert "hmac" not in d


def test_to_dict_includes_hmac_by_default():
    event = Event(agent_id="a")
    event.hmac = "somedigest"
    d = event.to_dict()
    assert d["hmac"] == "somedigest"


def test_to_dict_omits_none_payloads():
    event = Event(type=EventType.PROMPT, prompt=PromptData(content="hi"))
    d = event.to_dict()
    assert "response" not in d
    assert "tool_call" not in d
    assert "memory" not in d
    assert "reasoning" not in d
    assert "error" not in d


def test_to_dict_timestamp_is_iso():
    event = Event()
    d = event.to_dict()
    # Should be parseable as an ISO 8601 datetime
    parsed = datetime.fromisoformat(d["timestamp"])
    assert parsed.tzinfo is not None


def test_to_dict_tool_call_dicts_preserved():
    event = Event(
        type=EventType.TOOL_CALL,
        tool_call=ToolCallData(
            tool_name="calc",
            arguments={"x": 1, "y": 2},
            result={"sum": 3},
        ),
    )
    d = event.to_dict()
    assert d["tool_call"]["arguments"] == {"x": 1, "y": 2}
    assert d["tool_call"]["result"] == {"sum": 3}


# ---------------------------------------------------------------------------
# Event type / severity enum tests
# ---------------------------------------------------------------------------


def test_event_type_values():
    assert EventType.UNSPECIFIED == 0
    assert EventType.PROMPT == 1
    assert EventType.RESPONSE == 2
    assert EventType.TOOL_CALL == 3
    assert EventType.ERROR == 8


def test_severity_values():
    assert Severity.UNSPECIFIED == 0
    assert Severity.DEBUG == 1
    assert Severity.INFO == 2
    assert Severity.WARNING == 3
    assert Severity.ERROR == 4
    assert Severity.CRITICAL == 5


# ---------------------------------------------------------------------------
# Session-like grouping test (without grpc / Transponder)
# ---------------------------------------------------------------------------


def test_multiple_events_share_session_id():
    """Simulate what Session does — set a common session_id on events."""
    session_id = uuid7()
    events = []
    for content in ("prompt A", "prompt B", "prompt C"):
        e = Event(
            session_id=session_id,
            type=EventType.PROMPT,
            prompt=PromptData(content=content),
        )
        events.append(e)

    for e in events:
        assert e.session_id == session_id

    # Each event must have a distinct ID
    ids = [e.id for e in events]
    assert len(set(ids)) == len(ids)
