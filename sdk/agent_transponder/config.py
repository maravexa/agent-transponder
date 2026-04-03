"""
SDK configuration dataclass.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TransponderConfig:
    """Configuration for the Transponder SDK client."""

    # Connection
    endpoint: str = "localhost:8443"

    # mTLS material (paths to PEM files)
    ca_cert: Optional[str] = None
    client_cert: Optional[str] = None
    client_key: Optional[str] = None

    # HMAC signing key — shared secret between agent and ingestion API
    hmac_key: bytes = field(default_factory=bytes)

    # Agent identity
    agent_id: str = ""
    tenant_id: str = ""

    # Buffering / delivery
    queue_maxsize: int = 10_000  # Max events in the in-memory queue
    flush_interval_sec: float = 1.0  # How often the background sender wakes up
    max_batch_size: int = 100  # Events per gRPC call (stream mode)

    # Retry policy
    max_retries: int = 5
    retry_base_delay_sec: float = 0.5  # Initial backoff delay
    retry_max_delay_sec: float = 30.0  # Cap for exponential backoff

    # Graceful shutdown
    shutdown_timeout_sec: float = 10.0  # How long close() waits for flush
