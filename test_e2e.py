#!/usr/bin/env python3
"""End-to-end smoke test for Agent Transponder."""

from agent_transponder import Transponder
import time

# Initialize with the dev certs from task certs
tp = Transponder(
    endpoint="localhost:8443",
    ca_cert="certs/ca.pem",
    client_cert="certs/sdk-client.pem",
    client_key="certs/sdk-client-key.pem",
    hmac_key=b"test-hmac-key-change-me",
    agent_id="at-sdk-agent",
    tenant_id="smoke-test",
)

print("==> Pinging ingestion API...")
tp.ping()
print("    OK")

print("==> Sending test events...")
with tp.session() as session:
    # Simulate a simple agent interaction
    session.record_prompt(
        "What is the weather in New York?",
        role="user",
        model="gpt-4",
    )

    session.record_tool_call(
        tool_name="weather_api",
        args={"city": "New York"},
        result={"temp_f": 72, "conditions": "sunny"},
        success=True,
    )

    session.record_response(
        "The weather in New York is 72°F and sunny.",
        finish_reason="stop",
        tokens=15,
    )

    # Trigger a detectable pattern — repeated tool call (loop indicator)
    for i in range(5):
        session.record_tool_call(
            tool_name="weather_api",
            args={"city": "New York"},
            result={"temp_f": 72, "conditions": "sunny"},
            success=True,
        )

    session.record_error(
        code="TIMEOUT",
        message="API call timed out after 30s",
        retryable=True,
    )

print("    Events sent")

print("==> Flushing...")
tp.flush()
tp.close()
print("    Done")

print()
print("==> Verify the pipeline:")
print("    1. Check events landed:    docker exec <ingestion> ls /data/events/")
print("    2. Check audit log:        docker exec <ingestion> cat /data/audit/audit.jsonl | head -3")
print("    3. Check metrics:          curl -s localhost:9090/metrics | grep events_ingested")
print("    4. Check Grafana:          http://localhost:3000")
print()
print("Smoke test complete.")
