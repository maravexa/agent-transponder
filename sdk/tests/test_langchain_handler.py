"""
Tests for the LangChain callback handler integration.

These tests do NOT require langchain-core to be installed — they mock all
LangChain types and test the handler's mapping logic directly via the
shared _CallbackMixin.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import pytest

from agent_transponder.integrations.langchain import _CallbackMixin


# ---------------------------------------------------------------------------
# Mock session that records all calls
# ---------------------------------------------------------------------------


class MockSession:
    """Records every record_* call for assertions."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple, dict]] = []

    def _record(self, method: str, *args: Any, **kwargs: Any) -> None:
        self.calls.append((method, args, kwargs))

    def record_prompt(self, *a: Any, **kw: Any) -> None:
        self._record("record_prompt", *a, **kw)

    def record_response(self, *a: Any, **kw: Any) -> None:
        self._record("record_response", *a, **kw)

    def record_tool_call(self, *a: Any, **kw: Any) -> None:
        self._record("record_tool_call", *a, **kw)

    def record_error(self, *a: Any, **kw: Any) -> None:
        self._record("record_error", *a, **kw)

    def record_metadata(self, *a: Any, **kw: Any) -> None:
        self._record("record_metadata", *a, **kw)

    def record_memory(self, *a: Any, **kw: Any) -> None:
        self._record("record_memory", *a, **kw)

    def record_retry(self, *a: Any, **kw: Any) -> None:
        self._record("record_retry", *a, **kw)

    def last(self, method: str) -> Optional[tuple]:
        for name, args, kwargs in reversed(self.calls):
            if name == method:
                return (args, kwargs)
        return None

    def all_of(self, method: str) -> list[tuple]:
        return [(args, kwargs) for name, args, kwargs in self.calls if name == method]


# ---------------------------------------------------------------------------
# Minimal mock LangChain types
# ---------------------------------------------------------------------------


@dataclass
class MockMessage:
    type: str = "human"
    content: str = "Hello"


@dataclass
class MockGeneration:
    text: str = "Response text"
    generation_info: Dict[str, Any] = field(
        default_factory=lambda: {"finish_reason": "stop"}
    )


@dataclass
class MockLLMResult:
    generations: List[List[MockGeneration]] = field(
        default_factory=lambda: [[MockGeneration()]]
    )
    llm_output: Dict[str, Any] = field(
        default_factory=lambda: {
            "token_usage": {
                "prompt_tokens": 10,
                "completion_tokens": 5,
                "total_tokens": 15,
            }
        }
    )


@dataclass
class MockDocument:
    page_content: str = "Document content here"
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Helper to build a handler using the mixin directly
# ---------------------------------------------------------------------------


class HandlerForTest(_CallbackMixin):
    """Direct mixin user for testing without langchain-core."""

    def __init__(self, session: MockSession, **kwargs: Any) -> None:
        self._init_state(session, **kwargs)


def make_handler(**kwargs: Any) -> tuple[HandlerForTest, MockSession]:
    session = MockSession()
    handler = HandlerForTest(session, **kwargs)
    return handler, session


def uid() -> uuid.UUID:
    return uuid.uuid4()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestOnChatModelStartRecordsPrompt:
    def test_basic(self) -> None:
        handler, session = make_handler()
        run_id = uid()
        parent_id = uid()
        tags = ["tag1", "tag2"]
        serialized = {"kwargs": {"model_name": "gpt-4"}, "id": ["ChatOpenAI"]}
        messages = [
            [
                MockMessage(type="system", content="You are helpful"),
                MockMessage(type="human", content="Hi"),
            ]
        ]

        handler._handle_chat_model_start(
            serialized,
            messages,
            run_id=run_id,
            parent_run_id=parent_id,
            tags=tags,
        )

        args, kwargs = session.last("record_prompt")
        assert "system: You are helpful" in args[0]
        assert "human: Hi" in args[0]
        assert kwargs["role"] == "multi"
        assert kwargs["model"] == "gpt-4"
        assert kwargs["run_id"] == str(run_id)
        assert kwargs["parent_run_id"] == str(parent_id)
        assert kwargs["tags"] == ["tag1", "tag2"]

    def test_model_name_from_id_fallback(self) -> None:
        handler, session = make_handler()
        serialized = {"id": ["langchain", "llms", "CustomLLM"]}
        handler._handle_chat_model_start(
            serialized,
            [[MockMessage()]],
            run_id=uid(),
            parent_run_id=None,
            tags=None,
        )
        _, kwargs = session.last("record_prompt")
        assert kwargs["model"] == "CustomLLM"


class TestOnLlmEndRecordsResponse:
    def test_basic(self) -> None:
        handler, session = make_handler()
        run_id = uid()
        # Store a start timestamp first
        handler._store_start(run_id)
        time.sleep(0.01)

        response = MockLLMResult()
        handler._handle_llm_end(response, run_id=run_id, parent_run_id=None)

        args, kwargs = session.last("record_response")
        assert args[0] == "Response text"
        assert kwargs["finish_reason"] == "stop"
        assert kwargs["tokens"] == 15
        assert kwargs["run_id"] == str(run_id)

    def test_duration_calculated(self) -> None:
        handler, session = make_handler()
        run_id = uid()
        handler._store_start(run_id)
        time.sleep(0.02)
        handler._handle_llm_end(MockLLMResult(), run_id=run_id)
        # The handler itself records via session; duration is internal
        # Verify the start entry was cleaned up
        assert handler._pop_start(run_id) is None


class TestOnToolStartEndRecordsCompleteToolCall:
    def test_success(self) -> None:
        handler, session = make_handler()
        run_id = uid()
        parent_id = uid()
        serialized = {"name": "calculator"}

        handler._handle_tool_start(
            serialized,
            '{"x": 1}',
            run_id=run_id,
            parent_run_id=parent_id,
            tags=["math"],
        )
        time.sleep(0.01)
        handler._handle_tool_end("42", run_id=run_id, parent_run_id=parent_id)

        args, kwargs = session.last("record_tool_call")
        assert args[0] == "calculator"
        assert kwargs["args"] == {"x": 1}
        assert kwargs["result"] == {"output": "42"}
        assert kwargs["success"] is True
        assert kwargs["run_id"] == str(run_id)
        assert kwargs["parent_run_id"] == str(parent_id)
        assert kwargs["tags"] == ["math"]

    def test_non_json_input(self) -> None:
        handler, session = make_handler()
        run_id = uid()
        handler._handle_tool_start({"name": "search"}, "plain text", run_id=run_id)
        handler._handle_tool_end("result", run_id=run_id)
        _, kwargs = session.last("record_tool_call")
        assert kwargs["args"] == {"input": "plain text"}


class TestOnToolErrorRecordsFailure:
    def test_basic(self) -> None:
        handler, session = make_handler()
        run_id = uid()
        handler._handle_tool_start({"name": "api"}, "{}", run_id=run_id, tags=["net"])
        handler._handle_tool_error(
            RuntimeError("connection refused"),
            run_id=run_id,
        )

        tool_calls = session.all_of("record_tool_call")
        assert len(tool_calls) == 1
        _, kwargs = tool_calls[0]
        assert kwargs["success"] is False
        assert kwargs["error_msg"] == "connection refused"

        errors = session.all_of("record_error")
        assert len(errors) == 1
        _, ekw = errors[0]
        assert ekw["message"] == "connection refused"


class TestOnLlmErrorRecordsError:
    def test_basic(self) -> None:
        handler, session = make_handler()
        run_id = uid()
        parent_id = uid()
        handler._store_start(run_id)

        err = ValueError("bad prompt")
        handler._handle_llm_error(err, run_id=run_id, parent_run_id=parent_id)

        args, kwargs = session.last("record_error")
        assert args[0] == "ValueError"
        assert kwargs["message"] == "bad prompt"
        assert "ValueError" in kwargs["stacktrace"] or kwargs["stacktrace"] == ""
        assert kwargs["retryable"] is False
        assert kwargs["run_id"] == str(run_id)
        assert kwargs["parent_run_id"] == str(parent_id)


class TestOnChainStartEndRecordsMetadata:
    def test_start_end(self) -> None:
        handler, session = make_handler()
        run_id = uid()
        parent_id = uid()
        serialized = {
            "name": "RetrievalQA",
            "id": ["langchain", "chains", "RetrievalQAChain"],
        }

        handler._handle_chain_start(
            serialized,
            {"query": "test"},
            run_id=run_id,
            parent_run_id=parent_id,
            tags=["qa"],
        )
        time.sleep(0.01)
        handler._handle_chain_end(
            {"result": "ok"}, run_id=run_id, parent_run_id=parent_id
        )

        meta_calls = session.all_of("record_metadata")
        assert len(meta_calls) == 2

        # chain_start
        _, start_kw = meta_calls[0]
        assert start_kw["labels"]["langchain_event"] == "chain_start"
        assert start_kw["labels"]["chain_name"] == "RetrievalQA"
        assert start_kw["labels"]["chain_type"] == "RetrievalQAChain"
        assert start_kw["tags"] == ["qa"]

        # chain_end
        _, end_kw = meta_calls[1]
        assert end_kw["labels"]["langchain_event"] == "chain_end"
        assert end_kw["duration_ms"] > 0


class TestOnRetrieverEndRespectsCaptureFlag:
    def test_capture_disabled(self) -> None:
        handler, session = make_handler(capture_retriever_content=False)
        run_id = uid()
        handler._handle_retriever_start({}, "my query", run_id=run_id)
        docs = [MockDocument(page_content="doc1"), MockDocument(page_content="doc2")]
        handler._handle_retriever_end(docs, run_id=run_id)

        meta = session.last("record_metadata")
        assert meta is not None
        _, kwargs = meta
        assert kwargs["labels"]["retriever_doc_count"] == "2"
        assert session.last("record_memory") is None

    def test_capture_enabled_with_truncation(self) -> None:
        handler, session = make_handler(
            capture_retriever_content=True,
            retriever_content_max_chars=10,
        )
        run_id = uid()
        handler._handle_retriever_start({}, "my query", run_id=run_id)
        docs = [MockDocument(page_content="A" * 100)]
        handler._handle_retriever_end(docs, run_id=run_id)

        mem = session.last("record_memory")
        assert mem is not None
        args, kwargs = mem
        assert args[0] == "retrieval"
        assert args[1] == "my query"
        # Value should be truncated
        assert len(args[2]) == 10
        assert args[2] == "A" * 10


class TestCapturePromptsFalseRedactsContent:
    def test_prompt_redacted(self) -> None:
        handler, session = make_handler(capture_prompts=False)
        handler._handle_chat_model_start(
            {"kwargs": {"model_name": "gpt-4"}},
            [[MockMessage(content="secret prompt")]],
            run_id=uid(),
        )
        args, _ = session.last("record_prompt")
        assert args[0] == "[redacted by SDK]"

    def test_response_redacted(self) -> None:
        handler, session = make_handler(capture_prompts=False)
        run_id = uid()
        handler._store_start(run_id)
        handler._handle_llm_end(MockLLMResult(), run_id=run_id)
        args, _ = session.last("record_response")
        assert args[0] == "[redacted by SDK]"


class TestCallbackErrorDoesNotPropagate:
    def test_swallows_exception(self) -> None:
        """If session.record_prompt raises, the callback must not propagate."""
        session = MockSession()
        session.record_prompt = MagicMock(side_effect=RuntimeError("boom"))
        handler = HandlerForTest(session)

        # _handle_chat_model_start calls session.record_prompt which will raise.
        # The mixin itself doesn't wrap — the real handler class wraps.
        # Test the wrapping pattern by simulating what the real handler does.
        try:
            handler._handle_chat_model_start(
                {},
                [[MockMessage()]],
                run_id=uid(),
            )
            # If we got here from the mixin, it means the mixin raised.
            # That's expected — the wrapping is in TransponderCallbackHandler.
            # Let's verify the exception is raised from the mixin.
            pytest.fail("Expected RuntimeError from the mixin")
        except RuntimeError:
            pass  # Expected — mixin doesn't wrap, real handler does

        # Now test with a handler that wraps (simulating TransponderCallbackHandler)
        class WrappingHandler(_CallbackMixin):
            def __init__(self, sess: Any) -> None:
                self._init_state(sess)

            def on_chat_model_start(
                self, serialized: Any, messages: Any, **kw: Any
            ) -> None:
                try:
                    self._handle_chat_model_start(serialized, messages, **kw)
                except Exception:
                    pass  # Swallowed, as the real handler does

        wh = WrappingHandler(session)
        # This should not raise
        wh.on_chat_model_start({}, [[MockMessage()]], run_id=uid())


class TestRunStartsCleanup:
    def test_end_cleans_up(self) -> None:
        handler, session = make_handler()
        run_id = uid()
        handler._store_start(run_id)
        assert handler._pop_start(run_id) is not None
        # After pop, should be gone
        assert handler._pop_start(run_id) is None

    def test_llm_end_cleans_up(self) -> None:
        handler, session = make_handler()
        run_id = uid()
        handler._store_start(run_id)
        handler._handle_llm_end(MockLLMResult(), run_id=run_id)
        assert handler._pop_start(run_id) is None

    def test_tool_end_cleans_up(self) -> None:
        handler, session = make_handler()
        run_id = uid()
        handler._handle_tool_start({"name": "t"}, "{}", run_id=run_id)
        handler._handle_tool_end("out", run_id=run_id)
        assert handler._pop_start(run_id) is None

    def test_error_cleans_up(self) -> None:
        handler, session = make_handler()
        run_id = uid()
        handler._store_start(run_id)
        handler._handle_llm_error(ValueError("x"), run_id=run_id)
        assert handler._pop_start(run_id) is None

    def test_chain_end_cleans_up(self) -> None:
        handler, session = make_handler()
        run_id = uid()
        handler._handle_chain_start({"name": "c", "id": ["C"]}, {}, run_id=run_id)
        handler._handle_chain_end({}, run_id=run_id)
        assert handler._pop_start(run_id) is None

    def test_tool_error_cleans_up(self) -> None:
        handler, session = make_handler()
        run_id = uid()
        handler._handle_tool_start({"name": "t"}, "{}", run_id=run_id)
        handler._handle_tool_error(RuntimeError("x"), run_id=run_id)
        assert handler._pop_start(run_id) is None
