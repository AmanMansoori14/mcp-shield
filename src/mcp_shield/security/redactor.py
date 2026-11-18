"""Secret & PII redaction (TS-B5, MP-B4, MP-C3).

Runs on tool results before the model sees them *and* on everything written to the
audit store, so raw secrets never reach disk. Each mask names what it replaced:
``AKIA…[REDACTED:aws_access_key]``.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from mcp import types

from mcp_shield.audit.models import Finding


@dataclass(frozen=True)
class Pattern:
    kind: str
    regex: re.Pattern[str]
    keep: int = 4  # leading characters kept as a hint (0 for PII)


PATTERNS: tuple[Pattern, ...] = (
    Pattern(
        "private_key",
        re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----.*?-----END (?:[A-Z]+ )?PRIVATE KEY-----", re.S),
        0,
    ),
    Pattern("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    Pattern("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}")),
    Pattern("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    Pattern(
        "aws_secret_key",
        re.compile(r"(?i)aws.{0,20}?(?:secret|private).{0,20}?[\"'=:\s]([A-Za-z0-9/+=]{40})\b"),
    ),
    Pattern("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b")),
    Pattern("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    Pattern("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    Pattern("stripe_key", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}")),
    Pattern("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
    Pattern(
        "password_assignment",
        re.compile(r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key)\s*[=:]\s*[\"']?([^\s\"']{6,})"),
        0,
    ),
    Pattern("email", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), 0),
    Pattern(
        "phone",
        re.compile(
            r"(?<!\w)(?:\+?\d{1,3}[\s.\-]?)?(?:\(\d{2,4}\)|\d{2,4})[\s.\-]\d{3,4}[\s.\-]\d{3,4}(?!\w)"
        ),
        0,
    ),
)


class Redactor:
    def __init__(self, patterns: tuple[Pattern, ...] = PATTERNS, *, redact_pii: bool = True):
        self.patterns = tuple(p for p in patterns if redact_pii or p.kind not in ("email", "phone"))

    def redact_text(self, text: str) -> tuple[str, Counter[str]]:
        hits: Counter[str] = Counter()
        for p in self.patterns:
            text = p.regex.sub(_masker(p, hits), text)
        return text, hits

    def redact_value(self, value: Any) -> tuple[Any, Counter[str]]:
        """Redact every string inside a JSON-like value."""
        hits: Counter[str] = Counter()

        def walk(v: Any) -> Any:
            if isinstance(v, str):
                out, h = self.redact_text(v)
                hits.update(h)
                return out
            if isinstance(v, dict):
                return {k: walk(x) for k, x in v.items()}
            if isinstance(v, list):
                return [walk(x) for x in v]
            return v

        return walk(value), hits

    def redact_result(self, result: types.CallToolResult) -> tuple[types.CallToolResult, list[Finding]]:
        hits: Counter[str] = Counter()
        content: list[Any] = []
        for block in result.content:
            if isinstance(block, types.TextContent):
                text, h = self.redact_text(block.text)
                hits.update(h)
                content.append(block.model_copy(update={"text": text}))
            elif isinstance(block, types.EmbeddedResource) and isinstance(
                block.resource, types.TextResourceContents
            ):
                text, h = self.redact_text(block.resource.text)
                hits.update(h)
                content.append(
                    block.model_copy(update={"resource": block.resource.model_copy(update={"text": text})})
                )
            else:
                content.append(block)
        structured = result.structured_content
        if structured is not None:
            structured, h = self.redact_value(structured)
            hits.update(h)
        if not hits:
            return result, []
        findings = [
            Finding(
                stage="redaction",
                rule_id=f"redaction.{kind}",
                severity="medium" if kind not in ("email", "phone") else "low",
                excerpt_redacted=f"{n} occurrence(s) masked",
            )
            for kind, n in sorted(hits.items())
        ]
        return result.model_copy(update={"content": content, "structured_content": structured}), findings


def _masker(p: Pattern, hits: Counter[str]) -> Callable[[re.Match[str]], str]:
    def mask(m: re.Match[str]) -> str:
        hits[p.kind] += 1
        if m.groups() and m.group(1):  # mask only the captured secret, keep the label ("password=")
            start, end = m.span(1)
            whole = m.group(0)
            rel = start - m.start()
            return whole[:rel] + f"[REDACTED:{p.kind}]" + whole[rel + (end - start) :]
        hint = m.group(0)[: p.keep] + "…" if p.keep else ""
        return f"{hint}[REDACTED:{p.kind}]"

    return mask
