"""Policy engine and hot reload (TS-B1, TS-B2, MP-B2, IP-A17).

Rules match on server id and upstream tool name (globs), optionally on one argument
(path glob / not-glob / regex). Every matching rule contributes; the strictest action
wins: ``deny`` > ``require_approval`` > ``allow``. When no rule with an action
matches, ``defaults.action`` applies.

Upstream tool annotations are untrusted (MP-C7): ``destructiveHint: true`` can *add*
approval when ``approval.approve_destructive`` is on, but no hint ever removes a check.
"""

from __future__ import annotations

import fnmatch
import logging
import posixpath
import re
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from mcp_shield.config import ConfigError, PolicyFile, PolicyRule, load_yaml_model, policy_hash

log = logging.getLogger(__name__)

Action = Literal["allow", "deny", "require_approval"]
_RANK: dict[str, int] = {"allow": 0, "require_approval": 1, "deny": 2}


@dataclass(frozen=True)
class Decision:
    action: Action
    rule_ids: tuple[str, ...] = ()
    reason: str | None = None
    rate_limited: bool = False


@dataclass
class _Window:
    hits: deque[float] = field(default_factory=deque)


class PolicyEngine:
    def __init__(self, policy: PolicyFile, clock: Callable[[], float] = time.monotonic):
        self.policy = policy
        self.hash = policy_hash(policy)
        self._clock = clock
        self._windows: dict[str, _Window] = {}

    def evaluate(
        self,
        server_id: str,
        tool: str,
        arguments: dict[str, Any] | None,
        *,
        destructive_hint: bool | None = None,
    ) -> Decision:
        args = arguments or {}
        best: Action | None = None
        rule_ids: list[str] = []
        reason: str | None = None
        rate_limited = False

        for rule in self.policy.rules:
            if not _matches(rule, server_id, tool, args):
                continue
            if rule.rate_limit is not None and not self._allow_rate(rule):
                rate_limited = True
                rule_ids.append(rule.id)
                best = "deny"
                reason = (
                    f"rate limit {rule.rate_limit.calls} calls per {rule.rate_limit.per_s:g}s "
                    f"exceeded (rule {rule.id}); retry later"
                )
                continue
            if rule.action is None:
                continue
            rule_ids.append(rule.id)
            if best is None or _RANK[rule.action] > _RANK[best]:
                best = rule.action
                reason = _reason(rule, args)

        if (
            destructive_hint
            and self.policy.approval.approve_destructive
            and _RANK.get(best or "allow", 0) < 1
        ):
            best = "require_approval"
            rule_ids.append("annotation.destructive_hint")
            reason = "the upstream marks this tool as destructive"

        if best is None:
            best = self.policy.defaults.action
            if best == "deny":
                rule_ids.append("defaults.deny")
                reason = "no rule allows this tool (default deny)"
        return Decision(best, tuple(rule_ids), reason, rate_limited)

    def _allow_rate(self, rule: PolicyRule) -> bool:
        assert rule.rate_limit is not None
        now = self._clock()
        w = self._windows.setdefault(rule.id, _Window())
        while w.hits and now - w.hits[0] >= rule.rate_limit.per_s:
            w.hits.popleft()
        if len(w.hits) >= rule.rate_limit.calls:
            return False
        w.hits.append(now)
        return True


def _as_list(v: str | list[str] | None) -> list[str] | None:
    return None if v is None else [v] if isinstance(v, str) else v


def _matches(rule: PolicyRule, server_id: str, tool: str, args: dict[str, Any]) -> bool:
    servers = _as_list(rule.match.server)
    if servers is not None and not any(fnmatch.fnmatchcase(server_id, s) for s in servers):
        return False
    tools = _as_list(rule.match.tool)
    prefixed = f"{server_id}__{tool}"
    if tools is not None and not any(
        fnmatch.fnmatchcase(tool, t) or fnmatch.fnmatchcase(prefixed, t) for t in tools
    ):
        return False
    when = rule.when
    if when is None:
        return True
    if when.arg not in args:
        return False
    value = str(args[when.arg])
    if when.glob is not None and not path_match(value, when.glob):
        return False
    if when.not_glob is not None and path_match(value, when.not_glob):
        return False
    return not (when.regex is not None and not re.search(when.regex, value))


def _reason(rule: PolicyRule, args: dict[str, Any]) -> str:
    verb = {"deny": "denied", "require_approval": "requires approval", "allow": "allowed"}[
        rule.action or "allow"
    ]
    detail = ""
    if rule.when is not None and rule.when.arg in args:
        pattern = rule.when.not_glob or rule.when.glob or rule.when.regex
        relation = "is outside" if rule.when.not_glob else "matches"
        detail = f" ({rule.when.arg} {str(args[rule.when.arg])!r} {relation} {pattern!r})"
    return f"{verb} by rule {rule.id}{detail}"


def path_match(value: str, pattern: str) -> bool:
    """Glob match on a *normalised* path, so ``./sandbox/../../etc`` can't sneak past ``./sandbox/**``."""
    norm = posixpath.normpath(value) if value else value
    return bool(_glob_regex(_strip_dot(pattern)).match(norm))


def _strip_dot(p: str) -> str:
    return p[2:] if p.startswith("./") else p


@lru_cache(maxsize=256)
def _glob_regex(pattern: str) -> re.Pattern[str]:
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if pattern.startswith("**", i):
            out.append(".*")
            i += 2
            if i < len(pattern) and pattern[i] == "/":
                i += 1
            continue
        out.append("[^/]*" if c == "*" else "[^/]" if c == "?" else re.escape(c))
        i += 1
    return re.compile("^" + "".join(out) + "$")


class PolicyHolder:
    """The live policy. ``reload()`` validates first and swaps atomically; an invalid file keeps the old one."""

    def __init__(
        self,
        policy: PolicyFile,
        path: Path | None = None,
        *,
        on_swap: Callable[[PolicyEngine, str | None], None] | None = None,
    ):
        self.engine = PolicyEngine(policy)
        self.path = path
        self.on_swap = on_swap
        self.last_error: str | None = None
        self._mtime = path.stat().st_mtime_ns if path and path.exists() else None

    @property
    def policy(self) -> PolicyFile:
        return self.engine.policy

    @property
    def hash(self) -> str:
        return self.engine.hash

    def reload(self) -> bool:
        if self.path is None:
            return False
        try:
            new = load_yaml_model(self.path, PolicyFile)
        except ConfigError as e:
            self.last_error = str(e)
            log.error("policy reload rejected, keeping %s:\n%s", self.hash, e)
            return False
        self.last_error = None
        if policy_hash(new) == self.hash:
            return False
        self.engine = PolicyEngine(new)
        log.info("policy reloaded: %s", self.hash)
        if self.on_swap:
            self.on_swap(self.engine, self.path.read_text())
        return True

    def poll(self) -> bool:
        """Reload if the file's mtime changed. Called on an interval by the app (no extra dependency)."""
        if self.path is None:
            return False
        try:
            mtime = self.path.stat().st_mtime_ns
        except OSError:
            return False
        if mtime == self._mtime:
            return False
        self._mtime = mtime
        return self.reload()
