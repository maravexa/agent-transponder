#!/usr/bin/env python3
"""
Agent Transponder -- LangChain Integration Demo

Demonstrates AI agent observability by running three scripted
scenarios through LangChain with the TransponderCallbackHandler,
each designed to trigger a specific failure detector:

  Scenario 1: Task Loop     -- Agent repeats the same tool call in a loop
  Scenario 2: Tool Misuse   -- Agent hits consecutive tool failures
  Scenario 3: Goal Drift    -- Agent gradually drifts from its original task

Events flow through the full Agent Transponder pipeline:
  LangChain Agent -> SDK -> Ingester -> Analyzer -> Metrics Exporter

Requirements:
  pip install agent-transponder-sdk[langchain]

Usage:
  python examples/langchain_demo.py [OPTIONS]
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import random
import sys
import time
from datetime import datetime, timezone
from uuid import uuid4

UTC = timezone.utc

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------

_USE_COLOR = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    if not _USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


def _bold(t: str) -> str:
    return _c("1", t)


def _green(t: str) -> str:
    return _c("32", t)


def _red(t: str) -> str:
    return _c("31", t)


def _yellow(t: str) -> str:
    return _c("33", t)


def _cyan(t: str) -> str:
    return _c("36", t)


def _dim(t: str) -> str:
    return _c("2", t)


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

_SEPARATOR = "\u2550" * 63


def _banner(endpoint: str, agent_id: str, tenant_id: str) -> None:
    print(f"\n{_SEPARATOR}")
    print(_bold("  Agent Transponder -- LangChain Integration Demo"))
    print(
        f"  Endpoint: {_cyan(endpoint)} | Agent: {_cyan(agent_id)} "
        f"| Tenant: {_cyan(tenant_id)}"
    )
    print(_SEPARATOR)


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

def _check_langchain() -> None:
    try:
        import langchain_core  # noqa: F401
    except ImportError:
        print(
            _red("ERROR: langchain-core is not installed.\n")
            + "Install it with:\n"
            + "  pip install agent-transponder-sdk[langchain]\n"
            + "or:\n"
            + "  pip install langchain-core"
        )
        sys.exit(1)


def _define_tools():
    """Define and return the three LangChain tools."""
    from langchain_core.tools import tool, ToolException

    @tool
    def lookup_inventory(product_id: str) -> str:
        """Look up product inventory levels by product ID."""
        if product_id.startswith("INVALID-"):
            raise ToolException(f"Product not found: {product_id}")
        return json.dumps({
            "product_id": product_id,
            "name": f"Widget {product_id}",
            "stock": random.randint(0, 500),
            "warehouse": "us-east-1",
        })

    @tool
    def check_pricing(product_id: str) -> str:
        """Check current pricing for a product by product ID."""
        return json.dumps({
            "product_id": product_id,
            "price": round(random.uniform(9.99, 99.99), 2),
            "currency": "USD",
            "last_updated": datetime.now(UTC).isoformat(),
        })

    @tool
    def submit_order(product_id: str, quantity: int) -> str:
        """Submit a purchase order for a product."""
        return json.dumps({
            "order_id": f"ORD-{uuid4().hex[:8].upper()}",
            "product_id": product_id,
            "quantity": quantity,
            "status": "confirmed",
        })

    # Allow ToolException to propagate through LangChain's callback plumbing
    lookup_inventory.handle_tool_error = True

    return lookup_inventory, check_pricing, submit_order


# ---------------------------------------------------------------------------
# Scenario 1: Task Loop Detection
# ---------------------------------------------------------------------------

def run_loop_scenario(handler, session) -> int:
    """Repeat the same tool call 7 times to trigger the loop detector."""
    from langchain_core.language_models import FakeListChatModel

    print(f"\n{_bold('Scenario 1: Task Loop Detection')}")
    print(
        "  Objective: Trigger loop detector by repeating the same "
        "tool call 7 times"
    )

    _, check_pricing, _ = _define_tools()

    llm_responses = [
        "Let me verify the pricing for PROD-001.",
        "I should double-check that price for PROD-001.",
        "Rechecking PROD-001 pricing to make sure...",
        "Let me look at PROD-001 pricing one more time.",
        "Verifying PROD-001 pricing again for accuracy.",
        "One more price check on PROD-001 to be safe.",
        "Final verification of PROD-001 pricing.",
    ]
    llm = FakeListChatModel(responses=llm_responses)

    event_count = 0
    iterations = 7

    for i in range(iterations):
        step = f"[{i + 1}/{iterations}]"

        # LLM invocation
        result = llm.invoke("Check pricing for PROD-001", config={"callbacks": [handler]}).content
        print(f'  \u251c\u2500 {step} LLM -> "{result[:50]}"')
        event_count += 2  # prompt + response

        # Tool invocation
        tool_result = check_pricing.run("PROD-001", callbacks=[handler])
        parsed = json.loads(tool_result)
        print(f"  \u251c\u2500 {step} Tool check_pricing(PROD-001) -> ${parsed['price']}")
        event_count += 1  # tool call

    print(f"  \u2514\u2500 Done. {_green(str(event_count))} events recorded "
          f"({iterations} prompts + {iterations} responses + {iterations} tool calls)")
    print(
        f"  {_yellow('Expected detector trigger')}: "
        f"loop_detection (threshold: 5, actual: {iterations})"
    )
    return event_count


# ---------------------------------------------------------------------------
# Scenario 2: Tool Misuse Detection
# ---------------------------------------------------------------------------

def run_misuse_scenario(handler, session) -> int:
    """Generate 4 consecutive tool failures then 1 success."""
    from langchain_core.language_models import FakeListChatModel

    print(f"\n{_bold('Scenario 2: Tool Misuse Detection')}")
    print(
        "  Objective: Trigger tool misuse detector with 4 consecutive "
        "failures"
    )

    lookup_inventory, _, _ = _define_tools()

    llm_responses = [
        "Looking up inventory for INVALID-001...",
        "That didn't work, trying INVALID-002...",
        "Hmm, maybe INVALID-003 exists...",
        "One more try with INVALID-004...",
        "Let me try a valid product this time: PROD-042.",
    ]
    llm = FakeListChatModel(responses=llm_responses)

    event_count = 0
    invalid_ids = ["INVALID-001", "INVALID-002", "INVALID-003", "INVALID-004"]

    # Failing calls
    for i, pid in enumerate(invalid_ids):
        step = f"[{i + 1}/{len(invalid_ids) + 1}]"

        result = llm.invoke(f"Look up inventory for {pid}", config={"callbacks": [handler]}).content
        print(f'  \u251c\u2500 {step} LLM -> "{result[:50]}"')
        event_count += 2  # prompt + response

        # Use .run() so LangChain's callback plumbing fires on_tool_error
        tool_result = lookup_inventory.run(pid, callbacks=[handler])
        # When handle_tool_error=True, LangChain catches ToolException and
        # returns the error message as a string instead of raising.
        print(f"  \u251c\u2500 {step} Tool lookup_inventory({pid}) -> "
              f"{_red('ERROR')}: {tool_result}")
        event_count += 1  # tool call (error)

    # One successful call for contrast
    step = f"[5/{len(invalid_ids) + 1}]"
    result = llm.invoke("Look up inventory for PROD-042", config={"callbacks": [handler]}).content
    print(f'  \u251c\u2500 {step} LLM -> "{result[:50]}"')
    event_count += 2

    tool_result = lookup_inventory.run("PROD-042", callbacks=[handler])
    parsed = json.loads(tool_result)
    print(
        f"  \u251c\u2500 {step} Tool lookup_inventory(PROD-042) -> "
        f"{_green('OK')} Widget PROD-042 (stock: {parsed['stock']})"
    )
    event_count += 1

    print(f"  \u2514\u2500 Done. {_green(str(event_count))} events recorded "
          f"(5 prompts + 5 responses + 4 errors + 1 success)")
    print(
        f"  {_yellow('Expected detector trigger')}: "
        f"tool_misuse (threshold: 3, actual: 4)"
    )
    return event_count


# ---------------------------------------------------------------------------
# Scenario 3: Goal Drift Detection
# ---------------------------------------------------------------------------

def run_drift_scenario(handler, session) -> int:
    """Gradually shift prompts away from the original topic."""
    from langchain_core.language_models import FakeListChatModel

    print(f"\n{_bold('Scenario 3: Goal Drift Detection')}")
    print(
        "  Objective: Trigger drift detector by gradually shifting "
        "topic"
    )

    _, check_pricing, submit_order = _define_tools()

    prompts = [
        "Check inventory levels for our top-selling products",
        "What are the restocking recommendations for low-inventory items?",
        "How do supply chain delays affect our inventory forecasts?",
        "What are the latest global shipping route disruptions?",
        "Tell me about geopolitical factors affecting international trade",
        "What is the history of maritime trade routes in the Pacific?",
        "Recommend some good books about naval exploration history",
    ]

    llm_responses = [
        "I'll check inventory levels for the top sellers right away.",
        "Based on current stock, here are restocking recommendations.",
        "Supply chain delays have significant impact on forecasts.",
        "There are several major shipping route disruptions currently.",
        "Geopolitical tensions are reshaping international trade patterns.",
        "Pacific maritime trade routes have a fascinating history.",
        "Here are some excellent books on naval exploration.",
    ]
    llm = FakeListChatModel(responses=llm_responses)

    # Interleave some tool calls to make the scenario richer
    tool_calls = {
        0: ("check_pricing", check_pricing, "PROD-001"),
        2: ("check_pricing", check_pricing, "PROD-055"),
        4: ("submit_order", submit_order, "PROD-999"),
    }

    event_count = 0
    total = len(prompts)

    for i, prompt in enumerate(prompts):
        step = f"[{i + 1}/{total}]"

        # Send the prompt through the LLM
        result = llm.invoke(prompt, config={"callbacks": [handler]}).content
        print(f'  \u251c\u2500 {step} Prompt: "{prompt[:55]}..."')
        event_count += 2  # prompt + response

        # Interleaved tool calls
        if i in tool_calls:
            tool_name, tool_fn, pid = tool_calls[i]
            if tool_name == "submit_order":
                tool_result = tool_fn.run(
                    {"product_id": pid, "quantity": 10},
                    callbacks=[handler],
                )
            else:
                tool_result = tool_fn.run(pid, callbacks=[handler])
            parsed = json.loads(tool_result)
            label = parsed.get("price") or parsed.get("order_id", "")
            print(f"  \u251c\u2500 {step} Tool {tool_name}({pid}) -> {label}")
            event_count += 1

    print(f"  \u2514\u2500 Done. {_green(str(event_count))} events recorded")
    print(
        f"  {_yellow('Expected detector trigger')}: "
        "goal_drift (threshold: 0.7)"
    )
    return event_count


# ---------------------------------------------------------------------------
# Live mode (real LLM)
# ---------------------------------------------------------------------------

def run_live_mode(handler, session, model: str, tools: tuple) -> int:
    """Run an autonomous agent with a real LLM."""
    print(f"\n{_bold('Live Mode')}")
    print(
        f"  {_yellow('WARNING')}: Results are non-deterministic. "
        "Detectors may or may not trigger depending on LLM behaviour."
    )

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print(
            _red("\nERROR: OPENAI_API_KEY environment variable not set.\n")
            + "Set it with:\n"
            + '  export OPENAI_API_KEY="sk-..."'
        )
        return 0

    try:
        from langchain_openai import ChatOpenAI
        from langchain.agents import AgentExecutor, create_react_agent
        from langchain_core.prompts import PromptTemplate
    except ImportError:
        print(
            _red("\nERROR: langchain-openai is not installed.\n")
            + "Install it with:\n"
            + "  pip install langchain-openai langchain"
        )
        return 0

    llm = ChatOpenAI(model=model, temperature=0.7, callbacks=[handler])

    template = """You are an inventory management assistant. You have these tools:

{tools}

Use the following format:

Question: the input question
Thought: think about what to do
Action: the tool name
Action Input: the input to the tool
Observation: the result of the tool
... (repeat Thought/Action/Observation as needed)
Thought: I now know the final answer
Final Answer: the final answer

Question: {input}
Thought:{agent_scratchpad}"""

    prompt = PromptTemplate.from_template(template)
    lookup_inventory, check_pricing, submit_order = tools
    tool_list = [lookup_inventory, check_pricing, submit_order]
    agent = create_react_agent(llm, tool_list, prompt)
    executor = AgentExecutor(
        agent=agent,
        tools=tool_list,
        callbacks=[handler],
        verbose=True,
        max_iterations=10,
        handle_parsing_errors=True,
    )

    queries = [
        "Check inventory and pricing for PROD-001, PROD-002, and PROD-003.",
        "Submit an order for 50 units of the cheapest product you found.",
    ]

    for query in queries:
        print(f"\n  Query: {_cyan(query)}")
        try:
            result = executor.invoke({"input": query})
            print(f"  Result: {result.get('output', '')[:200]}")
        except Exception as exc:
            print(f"  {_red('Error')}: {exc}")

    return -1  # unknown count in live mode


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Agent Transponder -- LangChain Integration Demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--endpoint",
        default="localhost:8443",
        help="Ingester gRPC endpoint (default: localhost:8443)",
    )
    p.add_argument(
        "--ca-cert",
        default="/etc/flight-recorder/tls/ca/ca.crt",
        help="CA certificate path",
    )
    p.add_argument(
        "--client-cert",
        default="/etc/flight-recorder/tls/sdk/cert.pem",
        help="Client certificate path",
    )
    p.add_argument(
        "--client-key",
        default="/etc/flight-recorder/tls/sdk/key.pem",
        help="Client key path",
    )
    p.add_argument(
        "--hmac-key",
        default=None,
        help="HMAC signing key (default: AT_HMAC_KEY env var or 'demo-hmac-key')",
    )
    p.add_argument(
        "--agent-id",
        default="sdk-demo",
        help="Agent identifier; must match the TLS cert CN (default: sdk-demo)",
    )
    p.add_argument(
        "--tenant-id",
        default="demo",
        help="Tenant identifier (default: demo)",
    )
    p.add_argument(
        "--scenario",
        choices=["loop", "misuse", "drift", "all"],
        default="all",
        help="Run specific scenario (default: all)",
    )
    p.add_argument(
        "--live",
        action="store_true",
        help="Use a real LLM instead of FakeListLLM",
    )
    p.add_argument(
        "--model",
        default="gpt-4",
        help="Model name for --live mode (default: gpt-4)",
    )
    p.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    if args.verbose:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s %(name)s %(levelname)s %(message)s",
        )
    else:
        logging.basicConfig(
            level=logging.WARNING,
            format="%(asctime)s %(levelname)s %(message)s",
        )

    # Check langchain-core is available
    _check_langchain()

    from agent_transponder import Transponder
    from agent_transponder.integrations.langchain import TransponderCallbackHandler

    hmac_key = (
        args.hmac_key
        or os.environ.get("AT_HMAC_KEY")
        or "demo-hmac-key"
    )

    _banner(args.endpoint, args.agent_id, args.tenant_id)

    tp = Transponder(
        endpoint=args.endpoint,
        ca_cert=args.ca_cert,
        client_cert=args.client_cert,
        client_key=args.client_key,
        hmac_key=hmac_key.encode() if isinstance(hmac_key, str) else hmac_key,
        agent_id=args.agent_id,
        tenant_id=args.tenant_id,
    )

    total_events = 0
    sessions_created = 0
    detections: list[str] = []

    try:
        scenarios = (
            ["loop", "misuse", "drift"]
            if args.scenario == "all"
            else [args.scenario]
        )

        if args.live:
            tools = _define_tools()
            with tp.session() as session:
                handler = TransponderCallbackHandler(session)
                sessions_created += 1
                run_live_mode(handler, session, args.model, tools)
                total_events = -1  # unknown
        else:
            for scenario in scenarios:
                with tp.session() as session:
                    handler = TransponderCallbackHandler(session)
                    sessions_created += 1

                    if scenario == "loop":
                        total_events += run_loop_scenario(handler, session)
                        detections.append("loop")
                    elif scenario == "misuse":
                        total_events += run_misuse_scenario(handler, session)
                        detections.append("tool_misuse")
                    elif scenario == "drift":
                        total_events += run_drift_scenario(
                            handler, session
                        )
                        detections.append("goal_drift")

                # Brief pause between scenarios so timestamps are distinct
                if scenario != scenarios[-1]:
                    time.sleep(0.5)

        # Summary
        print(f"\n{_SEPARATOR}")
        print(_bold("  Summary"))
        print(f"  {'─' * 61}")
        if total_events >= 0:
            print(f"  Total events sent:     {_green(str(total_events))}")
        else:
            print(f"  Total events sent:     {_dim('(live mode — count unavailable)')}")
        print(f"  Sessions created:      {sessions_created}")
        if detections:
            print(
                f"  Expected detections:   {len(detections)} "
                f"({', '.join(detections)})"
            )
        print()
        print("  Next steps:")
        print(
            "  1. Check Prometheus: curl --cacert $CA "
            "https://localhost:9090/api/v1/query?"
            "query=flight_recorder_findings_total"
        )
        print("  2. Check Grafana:    https://localhost:3000 (admin/admin)")
        print(
            "  3. Check findings:   sudo cat "
            "/var/lib/flight-recorder/findings/*.jsonl | jq ."
        )
        print(_SEPARATOR + "\n")

    except ConnectionError as exc:
        print(f"\n{_red('ERROR')}: Could not connect to ingester at {args.endpoint}")
        print(f"  Detail: {exc}")
        print("\n  Troubleshooting:")
        print("  1. Is the ingester running?  systemctl status at-ingestion")
        print("  2. Check TLS certs exist:    ls -l /etc/flight-recorder/tls/")
        print("  3. Check firewall:           ss -tlnp | grep 8443")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n{_yellow('Interrupted')} — flushing pending events...")
    except Exception as exc:
        print(f"\n{_red('ERROR')}: {exc}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        else:
            print("  Run with --verbose for full traceback.")
        sys.exit(1)
    finally:
        tp.close()


if __name__ == "__main__":
    main()
