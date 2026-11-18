"""Pluggable tokenizers (TS-A6, IP-B1, gap #3).

Token counts are *estimates* of how much model context an MCP payload occupies
(MP-C1, MP-C6), and every row records which tokenizer produced it (MP-C4).

* ``anthropic`` - exact Claude counts from the ``count_tokens`` endpoint (needs credentials;
  results cached by content hash; falls back to the offline estimate if the API fails).
* ``tiktoken``  - offline default. It is *not* Claude's tokenizer and undercounts Claude
  tokens (typically 15-20%), so pair it with ``scale`` from ``shield calibrate``.
* ``char``      - len/4, used when tiktoken's encoding can't be loaded.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from collections import OrderedDict
from typing import Any, Protocol, runtime_checkable

log = logging.getLogger(__name__)

DEFAULT_CLAUDE_MODEL = "claude-opus-5-5"


@runtime_checkable
class Tokenizer(Protocol):
    name: str

    def count(self, text: str) -> int: ...


class CharHeuristicTokenizer:
    """~4 characters per token. Crude, but never fails."""

    name = "char:len/4"

    def count(self, text: str) -> int:
        return (len(text) + 3) // 4


class TiktokenTokenizer:
    def __init__(self, encoding: str = "o200k_base"):
        import tiktoken

        self._enc = tiktoken.get_encoding(encoding)
        self.name = f"tiktoken:{encoding}"

    def count(self, text: str) -> int:
        # disallowed_special=() so text that merely *contains* "<|endoftext|>" is counted, not rejected.
        return len(self._enc.encode(text, disallowed_special=()))


class ScaledTokenizer:
    """An offline estimate multiplied by a calibration factor measured with ``shield calibrate``."""

    def __init__(self, base: Tokenizer, scale: float):
        self.base = base
        self.scale = scale
        self.name = f"{base.name}*{scale:g}"

    def count(self, text: str) -> int:
        n = self.base.count(text)
        return round(n * self.scale) if n else 0


class AnthropicTokenizer:
    """Exact Claude token counts via ``messages.count_tokens``.

    ``count_tokens`` measures a whole request, so the fixed per-request overhead (measured
    once with a one-character message) is subtracted. Results are cached by content hash.
    Calls are blocking network I/O; the meter runs them on a worker thread (``remote = True``).
    """

    remote = True
    COOLDOWN_S = 30

    def __init__(
        self,
        model: str = DEFAULT_CLAUDE_MODEL,
        *,
        client: Any = None,
        fallback: Tokenizer | None = None,
        cache_size: int = 4096,
    ):
        if client is None:
            from anthropic import Anthropic

            client = Anthropic()  # resolves API key, auth token or `ant auth login` profile
        self.client = client
        self.model = model
        self.name = f"anthropic:{model}"
        self.fallback = fallback or CharHeuristicTokenizer()
        self.fallbacks = 0
        self.disabled = False  # set after an authentication failure: no point retrying
        self._retry_at = 0.0  # after other failures, use the fallback for a cool-down period
        self._overhead: int | None = None
        self._cache: OrderedDict[str, int] = OrderedDict()
        self._cache_size = cache_size
        self._lock = threading.Lock()

    def _raw(self, text: str) -> int:
        resp = self.client.messages.count_tokens(
            model=self.model, messages=[{"role": "user", "content": text}]
        )
        return int(resp.input_tokens)

    def overhead(self) -> int:
        if self._overhead is None:
            self._overhead = max(self._raw("a") - 1, 0)
        return self._overhead

    def count(self, text: str) -> int:
        if not text:
            return 0
        key = hashlib.sha256(text.encode()).hexdigest()
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                return self._cache[key]
        if self.disabled or time.monotonic() < self._retry_at:
            self.fallbacks += 1
            return self.fallback.count(text)
        try:
            n = max(self._raw(text) - self.overhead(), 0)
        except Exception as e:  # anthropic.APIConnectionError / RateLimitError / APIStatusError, ...
            self.fallbacks += 1
            if "authentication" in f"{type(e).__name__} {e}".lower():
                self.disabled = True
                log.warning("count_tokens has no valid credentials (%s); using %s", e, self.fallback.name)
            else:
                self._retry_at = time.monotonic() + self.COOLDOWN_S
                log.warning(
                    "count_tokens failed (%s); using %s for %ds", e, self.fallback.name, self.COOLDOWN_S
                )
            return self.fallback.count(text)
        with self._lock:
            self._cache[key] = n
            if len(self._cache) > self._cache_size:
                self._cache.popitem(last=False)
        return n


def make_tokenizer(
    kind: str = "tiktoken",
    encoding: str = "o200k_base",
    *,
    scale: float = 1.0,
    model: str = DEFAULT_CLAUDE_MODEL,
) -> Tokenizer:
    """Build the configured tokenizer; offline kinds fall back to the char heuristic (flagged by its name)."""
    offline: Tokenizer = CharHeuristicTokenizer()
    if kind in ("tiktoken", "anthropic"):
        try:
            offline = TiktokenTokenizer(encoding)
        except Exception as e:  # network-less first run, unknown encoding, ...
            log.warning("tiktoken unavailable (%s); falling back to char heuristic", e)
    if scale != 1.0:
        offline = ScaledTokenizer(offline, scale)
    if kind == "anthropic":
        try:
            return AnthropicTokenizer(model, fallback=offline)
        except Exception as e:  # SDK not installed (pip install 'mcp-shield[claude]') or no credentials
            log.warning("anthropic tokenizer unavailable (%s); using %s", e, offline.name)
    return offline
