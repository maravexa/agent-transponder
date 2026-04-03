"""
HMAC-SHA256 signing for Agent Transponder events.
Uses only stdlib — no extra crypto dependencies.
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .events import Event


def _canonical_json(event: "Event") -> bytes:
    """Return the canonical JSON bytes of an event, EXCLUDING the hmac field.

    Keys are sorted to ensure a deterministic serialisation regardless of
    insertion order.
    """
    d = event.to_dict(include_hmac=False)
    return json.dumps(d, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def sign_event(event: "Event", key: bytes) -> str:
    """Compute HMAC-SHA256 over the canonical JSON of *event*.

    Returns the hex-encoded digest and sets ``event.hmac`` in-place.
    """
    payload = _canonical_json(event)
    digest = _hmac.new(key, payload, hashlib.sha256).hexdigest()
    event.hmac = digest
    return digest


def verify_event(event: "Event", key: bytes) -> bool:
    """Verify the HMAC on *event*.

    Returns ``True`` if the stored HMAC matches the recomputed one.
    The comparison is constant-time to prevent timing attacks.
    """
    stored = event.hmac
    payload = _canonical_json(event)
    expected = _hmac.new(key, payload, hashlib.sha256).hexdigest()
    return _hmac.compare_digest(stored, expected)
