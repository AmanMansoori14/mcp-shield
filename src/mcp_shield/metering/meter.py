"""Token meter: what each MCP payload costs in model context (TS-A6, IP-B1).

* ``request_tokens``  - canonical JSON of the tool arguments; counted once per logical call.
* ``response_tokens`` - the result ``content`` the model receives. ``structuredContent`` is
  only counted when ``content`` is empty, because compliant tools also return it as text.
* ``schema_tokens``   - tool/prompt/resource definitions: a standing cost on every model turn.

Large payloads are counted on a worker thread so the event loop stays responsive.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

import anyio.to_thread
from mcp import types
from pydantic import BaseModel

from mcp_shield.metering.tokenizer import Tokenizer


@dataclass(frozen=True, slots=True)
class TokenUsage:
    request_tokens: int = 0
    response_tokens: int = 0
    schema_tokens: int = 0
    tokenizer: str = ""
    est_cost_usd: float | None = None
    estimated: bool = True

    @property
    def total_tokens(self) -> int:
        return self.request_tokens + self.response_tokens + self.schema_tokens


def canonical_json(value: Any) -> str:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json", by_alias=True, exclude_none=True)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


class Meter:
    def __init__(
        self,
        tokenizer: Tokenizer,
        *,
        image_tokens: int = 1500,
        offload_bytes: int = 32_768,
        input_price_per_million: float | None = None,
    ):
        self.tokenizer = tokenizer
        self.image_tokens = image_tokens
        self.offload_bytes = offload_bytes
        self.price = input_price_per_million

    # -- primitives -------------------------------------------------------

    async def count_text(self, text: str) -> int:
        if not text:
            return 0
        # Large payloads, and remote tokenizers (network calls), never block the event loop.
        if len(text) >= self.offload_bytes or getattr(self.tokenizer, "remote", False):
            return await anyio.to_thread.run_sync(self.tokenizer.count, text)
        return self.tokenizer.count(text)

    async def count_json(self, value: Any) -> int:
        if value is None or value == {}:
            return 0
        return await self.count_text(canonical_json(value))

    # -- MCP payloads -----------------------------------------------------

    async def request_tokens(self, arguments: dict[str, Any] | None) -> int:
        return await self.count_json(arguments or None)

    async def content_tokens(
        self,
        content: Sequence[types.ContentBlock] | Iterable[Any],
        structured: dict[str, Any] | None = None,
    ) -> int:
        total = 0
        blocks = list(content)
        for block in blocks:
            total += await self._block_tokens(block)
        if not blocks and structured:
            total += await self.count_json(structured)
        return total

    async def resource_contents_tokens(self, contents: Iterable[Any]) -> int:
        total = 0
        for c in contents:
            if isinstance(c, types.TextResourceContents):
                total += await self.count_text(c.text)
            elif isinstance(c, types.BlobResourceContents):
                total += self.image_tokens
        return total

    async def prompt_tokens(self, result: types.GetPromptResult) -> int:
        return await self.content_tokens([m.content for m in result.messages])

    async def definitions_tokens(self, items: Iterable[BaseModel]) -> int:
        """Name + description + schemas of listed tools/prompts/resources (their per-turn cost)."""
        total = 0
        for item in items:
            d = item.model_dump(mode="json", by_alias=True, exclude_none=True)
            d.pop("_meta", None)
            d.pop("icons", None)
            total += await self.count_json(d)
        return total

    def usage(self, *, request: int = 0, response: int = 0, schema: int = 0) -> TokenUsage:
        cost = None
        if self.price is not None:
            cost = round((request + response + schema) * self.price / 1_000_000, 8)
        return TokenUsage(
            request_tokens=request,
            response_tokens=response,
            schema_tokens=schema,
            tokenizer=self.tokenizer.name,
            est_cost_usd=cost,
        )

    async def _block_tokens(self, block: Any) -> int:
        if isinstance(block, types.TextContent):
            return await self.count_text(block.text)
        if isinstance(block, (types.ImageContent, types.AudioContent)):
            return self.image_tokens
        if isinstance(block, types.EmbeddedResource):
            return await self.resource_contents_tokens([block.resource])
        if isinstance(block, types.ResourceLink):
            return await self.count_json({"uri": str(block.uri), "name": block.name})
        if isinstance(block, BaseModel):
            return await self.count_json(block)
        return 0
