"""
Unit tests for agent_transponder.hmac — no gRPC required.
"""

from __future__ import annotations

import hashlib
import hmac as stdlib_hmac
import json

from agent_transponder.events import (
    ErrorData,
    Event,
    EventType,
    PromptData,
    ResponseData,
    ToolCallData,
)
from agent_transponder.hmac import sign_event, verify_event, _canonical_json


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

KEY_A = b"secret-key-alpha"
KEY_B = b"secret-key-beta"


def _make_prompt_event(**kwargs) -> Event:
    return Event(
        agent_id="test-agent",
        tenant_id="test-tenant",
        type=EventType.PROMPT,
        prompt=PromptData(content="Hello world", role="user"),
        **kwargs,
    )


# ---------------------------------------------------------------------------
# sign_event tests
# ---------------------------------------------------------------------------


def test_sign_event_sets_hmac_field():
    event = _make_prompt_event()
    assert event.hmac == ""
    digest = sign_event(event, KEY_A)
    assert event.hmac == digest
    assert len(digest) == 64  # SHA-256 hex = 64 chars


def test_sign_event_returns_hex_string():
    event = _make_prompt_event()
    digest = sign_event(event, KEY_A)
    # Must be valid hexadecimal
    int(digest, 16)


def test_sign_event_deterministic():
    """Same event + key must always produce the same digest."""
    e1 = _make_prompt_event()
    e2 = _make_prompt_event()
    # Force identical IDs and timestamps so canonical JSON is the same
    e2.id = e1.id
    e2.timestamp = e1.timestamp

    d1 = sign_event(e1, KEY_A)
    e1.hmac = ""  # reset so canonical JSON excludes it
    d2 = sign_event(e2, KEY_A)

    # Build canonical JSON manually for e1 (hmac already cleared)
    assert d1 == d2


def test_sign_event_different_keys_different_digest():
    e1 = _make_prompt_event()
    e2 = _make_prompt_event()
    e2.id = e1.id
    e2.timestamp = e1.timestamp

    d1 = sign_event(e1, KEY_A)
    d2 = sign_event(e2, KEY_B)
    assert d1 != d2


def test_sign_event_different_content_different_digest():
    e1 = Event(
        agent_id="agent",
        type=EventType.PROMPT,
        prompt=PromptData(content="Hello"),
    )
    e2 = Event(
        agent_id="agent",
        type=EventType.PROMPT,
        prompt=PromptData(content="Goodbye"),
    )
    # Force same id + timestamp to isolate content difference
    e2.id = e1.id
    e2.timestamp = e1.timestamp

    d1 = sign_event(e1, KEY_A)
    d2 = sign_event(e2, KEY_A)
    assert d1 != d2


def test_sign_event_overwrites_previous_hmac():
    event = _make_prompt_event()
    first = sign_event(event, KEY_A)
    # Sign again with the same key — HMAC field should be cleared in canonical
    # JSON before hashing, so we get the same result
    second = sign_event(event, KEY_A)
    assert first == second


# ---------------------------------------------------------------------------
# verify_event tests
# ---------------------------------------------------------------------------


def test_verify_event_valid():
    event = _make_prompt_event()
    sign_event(event, KEY_A)
    assert verify_event(event, KEY_A) is True


def test_verify_event_wrong_key():
    event = _make_prompt_event()
    sign_event(event, KEY_A)
    assert verify_event(event, KEY_B) is False


def test_verify_event_tampered_content():
    event = _make_prompt_event()
    sign_event(event, KEY_A)
    # Tamper with the event after signing
    event.agent_id = "evil-agent"
    assert verify_event(event, KEY_A) is False


def test_verify_event_tampered_hmac():
    event = _make_prompt_event()
    sign_event(event, KEY_A)
    event.hmac = "0" * 64  # Replace with zeroed digest
    assert verify_event(event, KEY_A) is False


def test_verify_event_empty_hmac():
    event = _make_prompt_event()
    # Never signed — hmac is empty string
    assert verify_event(event, KEY_A) is False


def test_verify_event_returns_bool():
    event = _make_prompt_event()
    sign_event(event, KEY_A)
    result = verify_event(event, KEY_A)
    assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# _canonical_json tests
# ---------------------------------------------------------------------------


def test_canonical_json_excludes_hmac():
    event = _make_prompt_event()
    event.hmac = "shouldbeexcluded"
    payload = _canonical_json(event)
    data = json.loads(payload)
    assert "hmac" not in data


def test_canonical_json_keys_sorted():
    event = _make_prompt_event()
    payload = _canonical_json(event)
    # Re-parse and re-serialise with sort_keys — should be identical
    data = json.loads(payload)
    reserialized = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)
    assert payload.decode("utf-8") == reserialized


def test_canonical_json_is_bytes():
    event = _make_prompt_event()
    payload = _canonical_json(event)
    assert isinstance(payload, bytes)


def test_canonical_json_stable_across_calls():
    event = _make_prompt_event()
    p1 = _canonical_json(event)
    p2 = _canonical_json(event)
    assert p1 == p2


def test_canonical_json_contains_required_fields():
    event = Event(
        agent_id="agt",
        tenant_id="tnt",
        type=EventType.ERROR,
        error=ErrorData(code="ERR", message="oops"),
    )
    payload = _canonical_json(event)
    data = json.loads(payload)
    assert data["agent_id"] == "agt"
    assert data["tenant_id"] == "tnt"
    assert data["type"] == int(EventType.ERROR)
    assert "error" in data
    assert data["error"]["code"] == "ERR"


# ---------------------------------------------------------------------------
# Cross-check: manual HMAC matches sign_event output
# ---------------------------------------------------------------------------


def test_sign_event_matches_manual_hmac():
    event = _make_prompt_event()
    payload = _canonical_json(event)
    expected = stdlib_hmac.new(KEY_A, payload, hashlib.sha256).hexdigest()
    actual = sign_event(event, KEY_A)
    assert actual == expected


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_sign_event_empty_key():
    """Empty key is allowed by stdlib hmac — just shouldn't raise."""
    event = _make_prompt_event()
    digest = sign_event(event, b"")
    assert len(digest) == 64


def test_sign_event_response_event():
    event = Event(
        agent_id="a",
        type=EventType.RESPONSE,
        response=ResponseData(content="ok", finish_reason="stop", token_count=2),
    )
    sign_event(event, KEY_A)
    assert verify_event(event, KEY_A) is True


def test_sign_event_tool_call_event():
    event = Event(
        agent_id="a",
        type=EventType.TOOL_CALL,
        tool_call=ToolCallData(
            tool_name="search",
            arguments={"q": "test"},
            result={"hits": 5},
            success=True,
        ),
    )
    sign_event(event, KEY_A)
    assert verify_event(event, KEY_A) is True
