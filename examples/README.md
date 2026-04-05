# Examples

## langchain_demo.py

Demonstrates the Agent Transponder LangChain integration by running
three scripted scenarios that each trigger a different failure detector.

### Prerequisites

- Agent Transponder stack running (ingester, analyzer, metrics exporter)
- Python SDK installed: `pip install -e sdk/[langchain]`

### Quick Start

```bash
# Run all scenarios against local dev stack
python examples/langchain_demo.py

# Run a specific scenario
python examples/langchain_demo.py --scenario loop

# With verbose output
python examples/langchain_demo.py --verbose

# With a real LLM
export OPENAI_API_KEY="sk-..."
python examples/langchain_demo.py --live --model gpt-4
```

### What to Check After Running

1. **Prometheus metrics**: findings counters should increment
2. **Grafana dashboard**: detection panels should show new data points
3. **Findings JSONL**: raw detector output on disk
4. **Events JSONL**: full telemetry captured from the agent

### Troubleshooting

**`ModuleNotFoundError: No module named 'agent_transponder'`**
Install the SDK: `pip install -e sdk/[langchain]`

**`Generated proto stubs not found`**
Generate them: `make proto-python`

**`PermissionError` on cert files**
The SDK needs read access to the TLS certs. Either run as a user
in the `flight-recorder` group, or copy certs to a user-readable
location.

**`HMAC signature mismatch`**
Ensure the agent ID (cert CN) has an HMAC key registered in the
ingester config at `/etc/flight-recorder/ingester.yml` under the
`agents:` section. The key must be base64-encoded.

**`no HMAC key registered for agent "X"`**
Add the agent to the ingester config and restart:
`sudo systemctl restart fr-ingester`
