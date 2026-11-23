"""Injection & poisoning scanner (TS-B3, MP-B3).

Deterministic rules, so every detection is explainable and testable:

* descriptions - prompt injection, exfiltration instructions, hidden unicode, tool shadowing
* results      - injection phrases, hidden unicode, markdown-image exfiltration
* arguments    - path traversal and sensitive paths (on path-like or command-like values),
                 shell injection (command-like values), exfil endpoints (anywhere)

Regex rules catch known phrasings, not paraphrases or translations. ``Scanner`` accepts an
optional ``Classifier`` (TS-B4) for those; it is a code-level hook, no model ships with it.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from mcp import types

from mcp_shield.audit.models import Finding

Target = Literal["description", "result", "args"]
Sev = Literal["info", "low", "medium", "high", "critical"]


@dataclass(frozen=True)
class Rule:
    id: str
    severity: Sev
    targets: tuple[Target, ...]
    pattern: re.Pattern[str]
    why: str


def _r(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


RULES: tuple[Rule, ...] = (
    Rule(
        "injection.ignore_previous",
        "high",
        ("description", "result"),
        _r(
            r"\b(ignore|disregard|forget|override)\b.{0,40}\b(all|any|previous|prior|above|earlier|preceding|your)\b.{0,30}\b(instructions?|prompts?|rules|guidelines|directions)"
        ),
        "tries to override the model's instructions",
    ),
    Rule(
        "injection.role_hijack",
        "high",
        ("description", "result"),
        _r(
            r"\b(you are now|from now on,? you|act as (an? )?(unrestricted|jailbroken|dan)\b|new system prompt|<\s*/?\s*system\s*>)"
        ),
        "tries to change the model's role or system prompt",
    ),
    Rule(
        "injection.hidden_tag",
        "medium",
        ("description", "result"),
        _r(r"<\s*(important|instructions?|secret|admin)\s*>"),
        "hides instructions in pseudo-tags the model may obey",
    ),
    Rule(
        "injection.conceal",
        "high",
        ("description", "result"),
        _r(r"\b(do not|don't|never)\b.{0,20}\b(tell|inform|mention|reveal|show)\b.{0,20}\b(the )?user\b"),
        "asks the model to hide its actions from the user",
    ),
    Rule(
        "exfil.instruction",
        "critical",
        ("description", "result"),
        _r(
            r"\b(read|cat|open|include|send|upload|attach|pass|post|copy)\b.{0,60}(~/\.ssh|id_rsa|id_ed25519|\.aws/credentials|\.env\b|/etc/passwd|private key|api[_ -]?keys?|credentials|passwords?)"
        ),
        "instructs the model to read or send secrets",
    ),
    Rule(
        "exfil.markdown_image",
        "high",
        ("result", "description"),
        _r(r"!\[[^\]]*\]\(\s*https?://[^)\s]+\?[^)\s]*=[^)\s]+\)"),
        "markdown image with query data: renders as a silent exfiltration request",
    ),
    Rule(
        "shadowing.cross_tool",
        "high",
        ("description",),
        _r(
            r"\b(when|before|after|whenever|instead of)\b.{0,30}\b(using|calling|you use|you call)\b.{0,30}\b(any|other|another|the [a-z0-9_]+) tools?\b"
        ),
        "tries to change how the model uses other tools",
    ),
    Rule("args.path_traversal", "high", ("args",), _r(r"(^|[\\/])\.\.([\\/]|$)"), "path traversal (..)"),
    Rule(
        "args.sensitive_path",
        "critical",
        ("args",),
        _r(
            r"(~|/home/[^/]+|/Users/[^/]+|/root)/\.(ssh|aws|gnupg|kube|docker)\b|/etc/(passwd|shadow|sudoers)|\bid_(rsa|ed25519|ecdsa)\b|\.env(\.|$|\b)"
        ),
        "reads a sensitive file",
    ),
    Rule(
        "args.shell_injection",
        "high",
        ("args",),
        _r(
            r"(\$\([^)]*\)|`[^`]+`|;\s*(rm|curl|wget|nc|bash|sh|python)\b|\|\s*(sh|bash)\b|&&\s*(rm|curl|wget)\b)"
        ),
        "shell command injection",
    ),
    Rule(
        "args.exfil_endpoint",
        "high",
        ("args",),
        _r(
            r"https?://([^/\s]*\.)?(webhook\.site|requestbin|pipedream\.net|ngrok(-free)?\.(io|app)|burpcollaborator|interact\.sh|pastebin\.com)|https?://\d{1,3}(\.\d{1,3}){3}"
        ),
        "sends data to a known exfiltration endpoint or raw IP",
    ),
)

# Zero-width, bidi overrides and Unicode "tag" characters: invisible to humans, readable by models.
_HIDDEN = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\U000e0000-\U000e007f]")


class Classifier(Protocol):
    """Optional ML scorer (TS-B4). Returns a probability that ``text`` is an injection."""

    def score(self, text: str) -> float: ...


@dataclass(frozen=True)
class ScanResult:
    findings: tuple[Finding, ...]

    @property
    def worst(self) -> Sev | None:
        order: list[Sev] = ["info", "low", "medium", "high", "critical"]
        present = {f.severity for f in self.findings}
        return next((s for s in reversed(order) if s in present), None)

    def __bool__(self) -> bool:
        return bool(self.findings)


class Scanner:
    def __init__(self, classifier: Classifier | None = None, threshold: float = 0.85):
        self.classifier = classifier
        self.threshold = threshold

    def scan(
        self, text: str, target: Target, *, label: str | None = None, only: frozenset[str] | None = None
    ) -> ScanResult:
        findings: list[Finding] = []
        if not text:
            return ScanResult(())
        hidden = _HIDDEN.findall(text)
        if hidden and target in ("description", "result"):
            findings.append(
                _finding(
                    f"unicode.hidden_{target}",
                    "high",
                    target,
                    text,
                    f"{len(hidden)} invisible character(s)",
                    label,
                )
            )
        visible = unicodedata.normalize("NFKC", _HIDDEN.sub("", text))
        for rule in RULES:
            if target not in rule.targets or (only is not None and rule.id not in only):
                continue
            m = rule.pattern.search(visible)
            if m:
                findings.append(_finding(rule.id, rule.severity, target, m.group(0), rule.why, label))
        if self.classifier is not None and target != "args":
            p = self.classifier.score(visible)
            if p >= self.threshold and not findings:
                findings.append(
                    _finding(
                        "classifier.injection",
                        "medium",
                        target,
                        visible[:120],
                        f"classifier score {p:.2f}",
                        label,
                    )
                )
        return ScanResult(tuple(findings))

    def scan_tool_definition(
        self, name: str, description: str | None, input_schema: dict[str, Any]
    ) -> ScanResult:
        """Descriptions *and* parameter descriptions: poison often hides in the schema."""
        parts = [description or "", *_schema_strings(input_schema)]
        return self.scan("\n".join(p for p in parts if p), "description", label=name)

    def scan_arguments(
        self,
        arguments: dict[str, Any] | None,
        *,
        tool: str | None = None,
        schema: dict[str, Any] | None = None,
    ) -> ScanResult:
        """Argument rules applied where they make sense, so markdown and code in a text field
        aren't refused: path rules on path-like values, shell rules on command-like ones,
        exfiltration endpoints anywhere. See ``argument_kinds``."""
        findings: list[Finding] = []
        command_tool = bool(tool and _COMMAND_TOOL.search(tool))
        for key, value in _flatten(arguments or {}):
            kinds = argument_kinds(key, value, schema, command_tool=command_tool)
            only = frozenset(rid for rid, needs in ARG_RULE_SCOPE.items() if needs & kinds)
            findings.extend(self.scan(value, "args", label=key, only=only).findings)
        return ScanResult(tuple(findings))


def _finding(rule_id: str, sev: Sev, target: str, snippet: str, why: str, label: str | None) -> Finding:
    excerpt = snippet if len(snippet) <= 160 else snippet[:157] + "…"
    return Finding(
        stage={"description": "description", "result": "result", "args": "args"}[target],
        rule_id=rule_id,
        severity=sev,
        target=label,
        snippet_hash=hashlib.sha256(snippet.encode()).hexdigest()[:16],
        excerpt_redacted=f"{why}: {excerpt!r}",
    )


def _schema_strings(schema: Any) -> Iterable[str]:
    if isinstance(schema, dict):
        for k, v in schema.items():
            if (k in ("description", "title") and isinstance(v, str)) or (
                k == "default" and isinstance(v, str)
            ):
                yield v
            else:
                yield from _schema_strings(v)
    elif isinstance(schema, list):
        for v in schema:
            yield from _schema_strings(v)


# Which argument rules apply to which kind of value.
ARG_RULE_SCOPE: dict[str, set[str]] = {
    "args.path_traversal": {"path", "command"},
    "args.sensitive_path": {"path", "command"},
    "args.shell_injection": {"command"},
    "args.exfil_endpoint": {"any"},
}
_PATH_NAME = re.compile(
    r"(?i)(^|_)(path|paths|file|files|filename|filepath|dir|directory|folder|uri|url|src|source|dest|"
    r"destination|target|location|root)$"
)
_COMMAND_NAME = re.compile(r"(?i)(^|_)(command|cmd|shell|script|exec|executable|commandline|cmdline)$")
_COMMAND_TOOL = re.compile(
    r"(?i)(^|_)(run|exec|execute|shell|bash|sh|command|terminal|spawn|subprocess)(_|$)"
)
_PATH_FORMATS = {"uri", "uri-reference", "iri", "iri-reference", "path", "file-path"}
_PATH_SHAPE = re.compile(r"^(/|~|\.{1,2}[/\\]|[A-Za-z]:[/\\]|file:|\\\\)\S*$")


def argument_kinds(
    key: str, value: str, schema: dict[str, Any] | None = None, *, command_tool: bool = False
) -> set[str]:
    """Classify one argument value as path-like and/or command-like (plus "any").

    path:    the argument's name says so (path, file, uri, dest, ...), its schema has a
             path/uri ``format``, or the whole value is shaped like a path (``../x``, ``~/x``,
             ``/etc/x``, ``C:\\x``) with no spaces.
    command: the name says so (command, cmd, script, ...) or the tool runs commands
             (run_*, exec, shell, bash, terminal, ...).
    """
    name = re.sub(r"\[\d+\]", "", key).rsplit(".", 1)[-1]
    kinds = {"any"}
    top = re.sub(r"\[\d+\]", "", key).split(".", 1)[0]
    prop = ((schema or {}).get("properties") or {}).get(top) or {}
    if _PATH_NAME.search(name) or prop.get("format") in _PATH_FORMATS or _PATH_SHAPE.match(value.strip()):
        kinds.add("path")
    if _COMMAND_NAME.search(name) or command_tool:
        kinds.add("command")
    return kinds


def result_strings(result: Any) -> list[str]:
    """Every string the model will read in a tool result: text blocks, embedded resource text
    and structured content (a malicious server can hide instructions in any of them)."""
    out: list[str] = []
    for block in getattr(result, "content", None) or []:
        if isinstance(block, types.TextContent):
            out.append(block.text)
        elif isinstance(block, types.EmbeddedResource) and isinstance(
            block.resource, types.TextResourceContents
        ):
            out.append(block.resource.text)
    structured = getattr(result, "structured_content", None)
    if structured:
        out.extend(v for _, v in _flatten(structured))
    return out


def _flatten(value: Any, prefix: str = "") -> Iterable[tuple[str, str]]:
    if isinstance(value, dict):
        for k, v in value.items():
            yield from _flatten(v, f"{prefix}.{k}" if prefix else str(k))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from _flatten(v, f"{prefix}[{i}]")
    elif isinstance(value, str):
        yield prefix, value
    elif value is not None:
        yield prefix, json.dumps(value)
