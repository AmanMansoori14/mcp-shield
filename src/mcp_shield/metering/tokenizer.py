"""Pluggable tokenizers (TS-A6, IP-B1).

Token counts are *estimates* of how much model context an MCP payload occupies
(MP-C1, MP-C6). ``tiktoken``'s ``o200k_base`` is the offline default; ``char``
(len/4) is the fallback when the encoding can't be loaded, and every count
records which tokenizer produced it (MP-C4).
"""

from __future__ import annotations

import logging
from typing import Protocol, runtime_checkable

log = logging.getLogger(__name__)


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


def make_tokenizer(kind: str = "tiktoken", encoding: str = "o200k_base") -> Tokenizer:
    """Build the configured tokenizer, falling back to the char heuristic (flagged by its name)."""
    if kind == "tiktoken":
        try:
            return TiktokenTokenizer(encoding)
        except Exception as e:  # network-less first run, unknown encoding, ...
            log.warning("tiktoken unavailable (%s); falling back to char heuristic", e)
    return CharHeuristicTokenizer()
