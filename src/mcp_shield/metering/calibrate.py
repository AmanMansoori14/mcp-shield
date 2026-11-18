"""Calibrate the offline token estimate against Claude's tokenizer (gap #3, PRD success marker ±10%).

``shield calibrate`` counts a corpus of MCP-shaped payloads (prose, JSON arguments, tool
definitions, logs, code) with both tokenizers, derives one scale factor, and reports the
per-sample error before and after scaling. Put the factor in ``tokenizer.scale``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from mcp_shield.metering.tokenizer import Tokenizer

_TOOL_DEF = {
    "name": "github__create_issue",
    "description": "Create a GitHub issue in a repository. Returns the issue number and URL.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "repo": {"type": "string", "description": "owner/name, e.g. 'acme/api'"},
            "title": {"type": "string"},
            "body": {"type": "string", "description": "Markdown body"},
            "labels": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["repo", "title"],
    },
}

CORPUS: list[tuple[str, str]] = [
    ("prose", "Welcome to MCP Shield. Every call you make through it is audited with its token cost. " * 20),
    (
        "prose-docs",
        (
            "To get started, install the package, copy the example configuration, and point your MCP client at "
            "the shield command. Policies are hot-reloaded; an invalid edit keeps the previous policy in place. "
        )
        * 15,
    ),
    ("json-args", json.dumps({"path": "./sandbox/notes/todo.md", "content": "- [ ] ship wave 3\n" * 40})),
    ("tool-definition", json.dumps(_TOOL_DEF)),
    ("tool-list", json.dumps([_TOOL_DEF] * 8)),
    (
        "logs",
        "\n".join(f"2026-11-18T10:00:{i % 60:02d}Z INFO request handled in {i % 97} ms" for i in range(300)),
    ),
    (
        "code",
        (
            "async def call_tool(ctx, params):\n"
            "    if params.name not in TOOLS:\n"
            "        raise MCPError(INVALID_PARAMS, f'Unknown tool: {params.name}')\n"
            "    return CallToolResult(content=[TextContent(type='text', text=str(params.arguments))])\n"
        )
        * 25,
    ),
    (
        "sql-result",
        "\n".join(
            f"| {i} | customer_{i} | {i * 13 % 997}.00 | 2026-11-{i % 28 + 1:02d} |" for i in range(200)
        ),
    ),
    (
        "markdown-table",
        "| tool | calls | tokens |\n|---|---:|---:|\n"
        + "\n".join(f"| server__tool_{i} | {i * 7} | {i * 1234} |" for i in range(120)),
    ),
    ("non-english", "Bonjour le monde. Ceci est un test du compteur de jetons. Grüße aus Berlin. " * 25),
]


@dataclass
class Sample:
    label: str
    reference: int
    estimate: int
    scaled: int = 0

    @property
    def error_before(self) -> float:
        return (self.estimate - self.reference) / self.reference

    @property
    def error_after(self) -> float:
        return (self.scaled - self.reference) / self.reference


@dataclass
class CalibrationReport:
    reference: str
    estimator: str
    scale: float
    samples: list[Sample] = field(default_factory=list)

    @property
    def worst_before(self) -> float:
        return max(abs(s.error_before) for s in self.samples)

    @property
    def worst_after(self) -> float:
        return max(abs(s.error_after) for s in self.samples)

    @property
    def within_10pct(self) -> bool:
        return self.worst_after <= 0.10


def calibrate(
    reference: Tokenizer, estimator: Tokenizer, corpus: list[tuple[str, str]] | None = None
) -> CalibrationReport:
    samples = []
    for label, text in corpus or CORPUS:
        ref = reference.count(text)
        if ref > 0:
            samples.append(Sample(label, ref, estimator.count(text)))
    if not samples:
        raise ValueError("calibration corpus produced no tokens")
    scale = round(sum(s.reference for s in samples) / max(sum(s.estimate for s in samples), 1), 3)
    for s in samples:
        s.scaled = round(s.estimate * scale)
    return CalibrationReport(reference.name, estimator.name, scale, samples)
