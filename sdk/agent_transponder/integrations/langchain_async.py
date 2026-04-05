"""
Async LangChain integration for Agent Transponder.

Provides ``AsyncTransponderCallbackHandler``, an async variant of the
LangChain callback handler.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

try:
    from langchain_core.callbacks import AsyncCallbackHandler

    HAS_LANGCHAIN = True
except ImportError:
    HAS_LANGCHAIN = False

from .langchain import _CallbackMixin

logger = logging.getLogger("agent_transponder.langchain")


if HAS_LANGCHAIN:

    class AsyncTransponderCallbackHandler(_CallbackMixin, AsyncCallbackHandler):
        """Async LangChain callback handler that records telemetry to Agent Transponder."""

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

        # -- AsyncCallbackHandler methods ---------------------------------

        async def on_chat_model_start(
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
                    serialized,
                    messages,
                    run_id=run_id,
                    parent_run_id=parent_run_id,
                    tags=tags,
                    metadata=metadata,
                    **kwargs,
                )
            except Exception:
                logger.exception("Error in on_chat_model_start callback")

        async def on_llm_start(
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
                    serialized,
                    prompts,
                    run_id=run_id,
                    parent_run_id=parent_run_id,
                    tags=tags,
                    metadata=metadata,
                    **kwargs,
                )
            except Exception:
                logger.exception("Error in on_llm_start callback")

        async def on_llm_end(
            self,
            response: Any,
            *,
            run_id: Any,
            parent_run_id: Any = None,
            **kwargs: Any,
        ) -> None:
            try:
                self._handle_llm_end(
                    response, run_id=run_id, parent_run_id=parent_run_id, **kwargs
                )
            except Exception:
                logger.exception("Error in on_llm_end callback")

        async def on_llm_error(
            self,
            error: BaseException,
            *,
            run_id: Any,
            parent_run_id: Any = None,
            **kwargs: Any,
        ) -> None:
            try:
                self._handle_llm_error(
                    error, run_id=run_id, parent_run_id=parent_run_id, **kwargs
                )
            except Exception:
                logger.exception("Error in on_llm_error callback")

        async def on_tool_start(
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
                    serialized,
                    input_str,
                    run_id=run_id,
                    parent_run_id=parent_run_id,
                    tags=tags,
                    metadata=metadata,
                    **kwargs,
                )
            except Exception:
                logger.exception("Error in on_tool_start callback")

        async def on_tool_end(
            self, output: Any, *, run_id: Any, parent_run_id: Any = None, **kwargs: Any
        ) -> None:
            try:
                self._handle_tool_end(
                    output, run_id=run_id, parent_run_id=parent_run_id, **kwargs
                )
            except Exception:
                logger.exception("Error in on_tool_end callback")

        async def on_tool_error(
            self,
            error: BaseException,
            *,
            run_id: Any,
            parent_run_id: Any = None,
            **kwargs: Any,
        ) -> None:
            try:
                self._handle_tool_error(
                    error, run_id=run_id, parent_run_id=parent_run_id, **kwargs
                )
            except Exception:
                logger.exception("Error in on_tool_error callback")

        async def on_chain_start(
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
                    serialized,
                    inputs,
                    run_id=run_id,
                    parent_run_id=parent_run_id,
                    tags=tags,
                    metadata=metadata,
                    **kwargs,
                )
            except Exception:
                logger.exception("Error in on_chain_start callback")

        async def on_chain_end(
            self,
            outputs: Dict[str, Any],
            *,
            run_id: Any,
            parent_run_id: Any = None,
            **kwargs: Any,
        ) -> None:
            try:
                self._handle_chain_end(
                    outputs, run_id=run_id, parent_run_id=parent_run_id, **kwargs
                )
            except Exception:
                logger.exception("Error in on_chain_end callback")

        async def on_chain_error(
            self,
            error: BaseException,
            *,
            run_id: Any,
            parent_run_id: Any = None,
            **kwargs: Any,
        ) -> None:
            try:
                self._handle_chain_error(
                    error, run_id=run_id, parent_run_id=parent_run_id, **kwargs
                )
            except Exception:
                logger.exception("Error in on_chain_error callback")

        async def on_retriever_start(
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
                    serialized,
                    query,
                    run_id=run_id,
                    parent_run_id=parent_run_id,
                    **kwargs,
                )
            except Exception:
                logger.exception("Error in on_retriever_start callback")

        async def on_retriever_end(
            self,
            documents: Any,
            *,
            run_id: Any,
            parent_run_id: Any = None,
            **kwargs: Any,
        ) -> None:
            try:
                self._handle_retriever_end(
                    documents,
                    run_id=run_id,
                    parent_run_id=parent_run_id,
                    **kwargs,
                )
            except Exception:
                logger.exception("Error in on_retriever_end callback")

        async def on_retry(
            self,
            retry_state: Any,
            *,
            run_id: Any,
            parent_run_id: Any = None,
            **kwargs: Any,
        ) -> None:
            try:
                self._handle_retry(
                    retry_state,
                    run_id=run_id,
                    parent_run_id=parent_run_id,
                    **kwargs,
                )
            except Exception:
                logger.exception("Error in on_retry callback")

else:

    class AsyncTransponderCallbackHandler:  # type: ignore[no-redef]
        """Stub that raises ImportError when langchain-core is not installed."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            raise ImportError(
                "langchain-core is required for the LangChain integration. "
                "Install it with: pip install agent-transponder-sdk[langchain]"
            )
