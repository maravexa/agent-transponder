"""
LangChain integration for Agent Transponder.

Provides ``TransponderCallbackHandler``, a LangChain ``BaseCallbackHandler``
that maps LangChain callback events to Agent Transponder telemetry.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import traceback
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

try:
    from langchain_core.callbacks import BaseCallbackHandler
    from langchain_core.outputs import LLMResult
    from langchain_core.messages import BaseMessage

    HAS_LANGCHAIN = True
except ImportError:
    HAS_LANGCHAIN = False

logger = logging.getLogger("agent_transponder.langchain")


def _format_messages(messages: List[List[BaseMessage]]) -> str:
    """Serialize chat messages to a human-readable string."""
    lines: list[str] = []
    for batch in messages:
        for msg in batch:
            role = getattr(msg, "type", "unknown")
            content = getattr(msg, "content", str(msg))
            lines.append(f"{role}: {content}")
    return "\n".join(lines)


def _extract_model_name(serialized: Dict[str, Any]) -> str:
    """Best-effort model name extraction from LangChain's serialized dict."""
    # Try kwargs.model_name first (ChatOpenAI etc.)
    model = serialized.get("kwargs", {}).get("model_name")
    if model:
        return model
    # Fall back to the last element of the id list
    id_list = serialized.get("id", [])
    if id_list:
        return id_list[-1]
    return "unknown"


class _CallbackMixin:
    """Shared mapping logic for sync and async LangChain callback handlers."""

    def _init_state(
        self,
        session: Any,
        *,
        capture_prompts: bool = True,
        capture_retriever_content: bool = False,
        retriever_content_max_chars: int = 2000,
    ) -> None:
        self._session = session
        self._capture_prompts = capture_prompts
        self._capture_retriever_content = capture_retriever_content
        self._retriever_content_max_chars = retriever_content_max_chars
        self._run_starts: Dict[str, Tuple[Any, ...]] = {}
        self._lock = threading.Lock()

    # -- helpers ----------------------------------------------------------

    def _store_start(self, run_id: Any, *data: Any) -> None:
        key = str(run_id)
        with self._lock:
            self._run_starts[key] = (time.monotonic(), *data)

    def _pop_start(self, run_id: Any) -> Optional[Tuple[Any, ...]]:
        key = str(run_id)
        with self._lock:
            return self._run_starts.pop(key, None)

    def _duration_ms(self, start_time: float) -> float:
        return (time.monotonic() - start_time) * 1000

    def _rid(self, run_id: Any) -> str:
        return str(run_id)

    def _prid(self, parent_run_id: Any) -> Optional[str]:
        return str(parent_run_id) if parent_run_id is not None else None

    # -- callback implementations -----------------------------------------

    def _handle_chat_model_start(
        self,
        serialized: Dict[str, Any],
        messages: List[List[Any]],
        *,
        run_id: Any,
        parent_run_id: Any = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        self._store_start(run_id)
        content = _format_messages(messages) if self._capture_prompts else "[redacted by SDK]"
        model = _extract_model_name(serialized)
        self._session.record_prompt(
            content,
            role="multi",
            model=model,
            run_id=self._rid(run_id),
            parent_run_id=self._prid(parent_run_id),
            tags=tags,
        )

    def _handle_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        *,
        run_id: Any,
        parent_run_id: Any = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        self._store_start(run_id)
        content = "\n".join(prompts) if self._capture_prompts else "[redacted by SDK]"
        model = _extract_model_name(serialized)
        self._session.record_prompt(
            content,
            role="user",
            model=model,
            run_id=self._rid(run_id),
            parent_run_id=self._prid(parent_run_id),
            tags=tags,
        )

    def _handle_llm_end(
        self,
        response: Any,
        *,
        run_id: Any,
        parent_run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        start_data = self._pop_start(run_id)
        duration_ms = self._duration_ms(start_data[0]) if start_data else 0.0

        # Extract text from first generation
        content = "[redacted by SDK]"
        finish_reason = "unknown"
        try:
            gen = response.generations[0][0]
            if self._capture_prompts:
                content = gen.text
            gen_info = getattr(gen, "generation_info", None) or {}
            finish_reason = gen_info.get("finish_reason", "unknown")
        except (IndexError, AttributeError):
            if self._capture_prompts:
                content = str(response)

        # Extract token usage
        tokens = 0
        llm_output = getattr(response, "llm_output", None) or {}
        token_usage = llm_output.get("token_usage", {})
        if token_usage:
            tokens = token_usage.get("total_tokens", 0)

        self._session.record_response(
            content,
            finish_reason=finish_reason,
            tokens=tokens,
            run_id=self._rid(run_id),
            parent_run_id=self._prid(parent_run_id),
        )

    def _handle_llm_error(
        self,
        error: BaseException,
        *,
        run_id: Any,
        parent_run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        self._pop_start(run_id)
        try:
            tb = "".join(traceback.format_exception(type(error), error, error.__traceback__))
        except Exception:
            tb = ""
        self._session.record_error(
            type(error).__name__,
            message=str(error),
            stacktrace=tb,
            retryable=False,
            run_id=self._rid(run_id),
            parent_run_id=self._prid(parent_run_id),
        )

    def _handle_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        *,
        run_id: Any,
        parent_run_id: Any = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        tool_name = serialized.get("name", serialized.get("id", ["unknown"])[-1])
        self._store_start(run_id, tool_name, input_str, tags, parent_run_id)

    def _handle_tool_end(
        self,
        output: Any,
        *,
        run_id: Any,
        parent_run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        start_data = self._pop_start(run_id)
        if start_data is None:
            return
        start_time, tool_name, input_str, tags, stored_parent = start_data
        duration_ms = self._duration_ms(start_time)

        try:
            args = json.loads(input_str)
        except (json.JSONDecodeError, TypeError):
            args = {"input": input_str}

        self._session.record_tool_call(
            tool_name,
            args=args,
            result={"output": str(output)},
            success=True,
            run_id=self._rid(run_id),
            parent_run_id=self._prid(parent_run_id),
            tags=tags,
        )

    def _handle_tool_error(
        self,
        error: BaseException,
        *,
        run_id: Any,
        parent_run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        start_data = self._pop_start(run_id)
        tool_name = "unknown"
        tags = None
        if start_data is not None:
            _, tool_name, _, tags, _ = start_data

        self._session.record_tool_call(
            tool_name,
            success=False,
            error_msg=str(error),
            run_id=self._rid(run_id),
            parent_run_id=self._prid(parent_run_id),
            tags=tags,
        )
        self._session.record_error(
            type(error).__name__,
            message=str(error),
            run_id=self._rid(run_id),
            parent_run_id=self._prid(parent_run_id),
        )

    def _handle_chain_start(
        self,
        serialized: Dict[str, Any],
        inputs: Dict[str, Any],
        *,
        run_id: Any,
        parent_run_id: Any = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        self._store_start(run_id)
        chain_name = serialized.get("name", "unknown")
        id_list = serialized.get("id", [""])
        chain_type = id_list[-1] if id_list else "unknown"
        self._session.record_metadata(
            labels={
                "langchain_event": "chain_start",
                "chain_name": chain_name,
                "chain_type": chain_type,
            },
            run_id=self._rid(run_id),
            parent_run_id=self._prid(parent_run_id),
            tags=tags,
        )

    def _handle_chain_end(
        self,
        outputs: Dict[str, Any],
        *,
        run_id: Any,
        parent_run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        start_data = self._pop_start(run_id)
        duration_ms = self._duration_ms(start_data[0]) if start_data else 0.0
        self._session.record_metadata(
            labels={"langchain_event": "chain_end"},
            run_id=self._rid(run_id),
            parent_run_id=self._prid(parent_run_id),
            duration_ms=duration_ms,
        )

    def _handle_chain_error(
        self,
        error: BaseException,
        *,
        run_id: Any,
        parent_run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        self._pop_start(run_id)
        self._session.record_error(
            type(error).__name__,
            message=str(error),
            run_id=self._rid(run_id),
            parent_run_id=self._prid(parent_run_id),
        )

    def _handle_retriever_start(
        self,
        serialized: Dict[str, Any],
        query: str,
        *,
        run_id: Any,
        parent_run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        self._store_start(run_id, query)

    def _handle_retriever_end(
        self,
        documents: Any,
        *,
        run_id: Any,
        parent_run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        start_data = self._pop_start(run_id)
        query = start_data[1] if start_data else ""

        if not self._capture_retriever_content:
            self._session.record_metadata(
                labels={
                    "langchain_event": "retriever_end",
                    "retriever_doc_count": str(len(documents)),
                },
                run_id=self._rid(run_id),
                parent_run_id=self._prid(parent_run_id),
            )
        else:
            max_chars = self._retriever_content_max_chars
            parts = []
            for doc in documents:
                text = getattr(doc, "page_content", str(doc))
                parts.append(text[:max_chars])
            value = "\n---\n".join(parts)
            self._session.record_memory(
                "retrieval",
                query,
                value,
                run_id=self._rid(run_id),
                parent_run_id=self._prid(parent_run_id),
            )

    def _handle_retry(
        self,
        retry_state: Any,
        *,
        run_id: Any,
        parent_run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        self._session.record_retry(
            run_id=self._rid(run_id),
            parent_run_id=self._prid(parent_run_id),
        )


if HAS_LANGCHAIN:

    class TransponderCallbackHandler(_CallbackMixin, BaseCallbackHandler):
        """LangChain callback handler that records telemetry to Agent Transponder."""

        def __init__(
            self,
            session: Any,
            *,
            capture_prompts: bool = True,
            capture_retriever_content: bool = False,
            retriever_content_max_chars: int = 2000,
        ) -> None:
            super().__init__()
            self._init_state(
                session,
                capture_prompts=capture_prompts,
                capture_retriever_content=capture_retriever_content,
                retriever_content_max_chars=retriever_content_max_chars,
            )

        # -- BaseCallbackHandler methods ----------------------------------

        def on_chat_model_start(
            self,
            serialized: Dict[str, Any],
            messages: List[List[Any]],
            *,
            run_id: Any,
            parent_run_id: Any = None,
            tags: Optional[List[str]] = None,
            metadata: Optional[Dict[str, Any]] = None,
            **kwargs: Any,
        ) -> None:
            try:
                self._handle_chat_model_start(
                    serialized, messages, run_id=run_id,
                    parent_run_id=parent_run_id, tags=tags, metadata=metadata,
                    **kwargs,
                )
            except Exception:
                logger.exception("Error in on_chat_model_start callback")

        def on_llm_start(
            self,
            serialized: Dict[str, Any],
            prompts: List[str],
            *,
            run_id: Any,
            parent_run_id: Any = None,
            tags: Optional[List[str]] = None,
            metadata: Optional[Dict[str, Any]] = None,
            **kwargs: Any,
        ) -> None:
            try:
                self._handle_llm_start(
                    serialized, prompts, run_id=run_id,
                    parent_run_id=parent_run_id, tags=tags, metadata=metadata,
                    **kwargs,
                )
            except Exception:
                logger.exception("Error in on_llm_start callback")

        def on_llm_end(
            self, response: Any, *, run_id: Any, parent_run_id: Any = None, **kwargs: Any
        ) -> None:
            try:
                self._handle_llm_end(response, run_id=run_id, parent_run_id=parent_run_id, **kwargs)
            except Exception:
                logger.exception("Error in on_llm_end callback")

        def on_llm_error(
            self, error: BaseException, *, run_id: Any, parent_run_id: Any = None, **kwargs: Any
        ) -> None:
            try:
                self._handle_llm_error(error, run_id=run_id, parent_run_id=parent_run_id, **kwargs)
            except Exception:
                logger.exception("Error in on_llm_error callback")

        def on_tool_start(
            self,
            serialized: Dict[str, Any],
            input_str: str,
            *,
            run_id: Any,
            parent_run_id: Any = None,
            tags: Optional[List[str]] = None,
            metadata: Optional[Dict[str, Any]] = None,
            **kwargs: Any,
        ) -> None:
            try:
                self._handle_tool_start(
                    serialized, input_str, run_id=run_id,
                    parent_run_id=parent_run_id, tags=tags, metadata=metadata,
                    **kwargs,
                )
            except Exception:
                logger.exception("Error in on_tool_start callback")

        def on_tool_end(
            self, output: Any, *, run_id: Any, parent_run_id: Any = None, **kwargs: Any
        ) -> None:
            try:
                self._handle_tool_end(output, run_id=run_id, parent_run_id=parent_run_id, **kwargs)
            except Exception:
                logger.exception("Error in on_tool_end callback")

        def on_tool_error(
            self, error: BaseException, *, run_id: Any, parent_run_id: Any = None, **kwargs: Any
        ) -> None:
            try:
                self._handle_tool_error(error, run_id=run_id, parent_run_id=parent_run_id, **kwargs)
            except Exception:
                logger.exception("Error in on_tool_error callback")

        def on_chain_start(
            self,
            serialized: Dict[str, Any],
            inputs: Dict[str, Any],
            *,
            run_id: Any,
            parent_run_id: Any = None,
            tags: Optional[List[str]] = None,
            metadata: Optional[Dict[str, Any]] = None,
            **kwargs: Any,
        ) -> None:
            try:
                self._handle_chain_start(
                    serialized, inputs, run_id=run_id,
                    parent_run_id=parent_run_id, tags=tags, metadata=metadata,
                    **kwargs,
                )
            except Exception:
                logger.exception("Error in on_chain_start callback")

        def on_chain_end(
            self, outputs: Dict[str, Any], *, run_id: Any, parent_run_id: Any = None, **kwargs: Any
        ) -> None:
            try:
                self._handle_chain_end(outputs, run_id=run_id, parent_run_id=parent_run_id, **kwargs)
            except Exception:
                logger.exception("Error in on_chain_end callback")

        def on_chain_error(
            self, error: BaseException, *, run_id: Any, parent_run_id: Any = None, **kwargs: Any
        ) -> None:
            try:
                self._handle_chain_error(error, run_id=run_id, parent_run_id=parent_run_id, **kwargs)
            except Exception:
                logger.exception("Error in on_chain_error callback")

        def on_retriever_start(
            self,
            serialized: Dict[str, Any],
            query: str,
            *,
            run_id: Any,
            parent_run_id: Any = None,
            **kwargs: Any,
        ) -> None:
            try:
                self._handle_retriever_start(
                    serialized, query, run_id=run_id,
                    parent_run_id=parent_run_id, **kwargs,
                )
            except Exception:
                logger.exception("Error in on_retriever_start callback")

        def on_retriever_end(
            self, documents: Any, *, run_id: Any, parent_run_id: Any = None, **kwargs: Any
        ) -> None:
            try:
                self._handle_retriever_end(
                    documents, run_id=run_id, parent_run_id=parent_run_id, **kwargs,
                )
            except Exception:
                logger.exception("Error in on_retriever_end callback")

        def on_retry(
            self, retry_state: Any, *, run_id: Any, parent_run_id: Any = None, **kwargs: Any
        ) -> None:
            try:
                self._handle_retry(
                    retry_state, run_id=run_id, parent_run_id=parent_run_id, **kwargs,
                )
            except Exception:
                logger.exception("Error in on_retry callback")

else:

    class TransponderCallbackHandler:  # type: ignore[no-redef]
        """Stub that raises ImportError when langchain-core is not installed."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            raise ImportError(
                "langchain-core is required for the LangChain integration. "
                "Install it with: pip install agent-transponder-sdk[langchain]"
            )
