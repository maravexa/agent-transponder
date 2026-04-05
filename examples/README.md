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
