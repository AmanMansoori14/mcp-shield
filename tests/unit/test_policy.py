"""TS-B1 policy engine and TS-B2 hot reload."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_shield.config import PolicyFile
from mcp_shield.security.policy import PolicyEngine, PolicyHolder, path_match


def engine(rules: list[dict[str, object]], **extra: object) -> PolicyEngine:
    return PolicyEngine(PolicyFile.model_validate({"rules": rules, **extra}))


SANDBOX_RULE = {
    "id": "deny-write-outside-sandbox",
    "match": {"server": "fs", "tool": "write_file"},
    "when": {"arg": "path", "not_glob": "./sandbox/**"},
    "action": "deny",
}


@pytest.mark.parametrize(
    ("path", "allowed"),
    [
        ("./sandbox/notes.md", True),
        ("sandbox/a/b/c.txt", True),
        ("/etc/passwd", False),
        ("./sandbox/../../etc/passwd", False),  # normalised before matching
        ("../sandbox/x", False),
        ("sandboxed/x", False),
    ],
)
def test_path_rule_normalises_paths(path: str, allowed: bool) -> None:
    d = engine([SANDBOX_RULE]).evaluate("fs", "write_file", {"path": path})
    assert (d.action == "allow") is allowed
    if not allowed:
        assert d.rule_ids == ("deny-write-outside-sandbox",)
        assert "is outside './sandbox/**'" in (d.reason or "")


def test_rule_only_applies_to_its_server_and_tool() -> None:
    e = engine([SANDBOX_RULE])
    assert e.evaluate("other", "write_file", {"path": "/etc/x"}).action == "allow"
    assert e.evaluate("fs", "read_file", {"path": "/etc/x"}).action == "allow"


def test_tool_globs_match_plain_and_prefixed_names() -> None:
    e = engine(
        [
            {
                "id": "approve-destructive",
                "match": {"tool": ["delete_*", "*_merge"]},
                "action": "require_approval",
            }
        ]
    )
    assert e.evaluate("gh", "delete_repo", {}).action == "require_approval"
    assert e.evaluate("gh", "pull_request_merge", {}).action == "require_approval"
    assert e.evaluate("gh", "list_repos", {}).action == "allow"
    e2 = engine([{"id": "x", "match": {"tool": "gh__*"}, "action": "deny"}])
    assert e2.evaluate("gh", "anything", {}).action == "deny"


def test_strictest_action_wins() -> None:
    e = engine(
        [
            {"id": "allow-all", "action": "allow"},
            {"id": "approve-gh", "match": {"server": "gh"}, "action": "require_approval"},
            {"id": "deny-delete", "match": {"tool": "delete_*"}, "action": "deny"},
        ]
    )
    assert e.evaluate("gh", "list", {}).action == "require_approval"
    d = e.evaluate("gh", "delete_repo", {})
    assert d.action == "deny" and set(d.rule_ids) == {"allow-all", "approve-gh", "deny-delete"}


def test_default_deny_with_explicit_allow() -> None:
    e = engine(
        [{"id": "allow-notes", "match": {"server": "notes"}, "action": "allow"}], defaults={"action": "deny"}
    )
    assert e.evaluate("notes", "echo", {}).action == "allow"
    d = e.evaluate("fs", "read", {})
    assert d.action == "deny" and d.rule_ids == ("defaults.deny",)


def test_destructive_hint_only_tightens() -> None:
    e = engine([])
    assert e.evaluate("x", "drop", {}, destructive_hint=True).action == "require_approval"
    assert e.evaluate("x", "drop", {}, destructive_hint=False).action == "allow"
    # A deny is never softened by a hint, and approval can be switched off by policy (not by the upstream).
    e2 = engine([{"id": "deny", "action": "deny"}])
    assert e2.evaluate("x", "drop", {}, destructive_hint=True).action == "deny"
    e3 = engine([], approval={"approve_destructive": False})
    assert e3.evaluate("x", "drop", {}, destructive_hint=True).action == "allow"


def test_regex_condition() -> None:
    e = engine([{"id": "no-prod", "when": {"arg": "env", "regex": "^prod"}, "action": "deny"}])
    assert e.evaluate("x", "deploy", {"env": "production"}).action == "deny"
    assert e.evaluate("x", "deploy", {"env": "staging"}).action == "allow"
    assert e.evaluate("x", "deploy", {}).action == "allow"  # missing arg: rule doesn't apply


def test_rate_limit_sliding_window() -> None:
    now = [0.0]
    e = PolicyEngine(
        PolicyFile.model_validate(
            {"rules": [{"id": "rl", "match": {"server": "gh"}, "rate_limit": {"calls": 2, "per_s": 10}}]}
        ),
        clock=lambda: now[0],
    )
    assert e.evaluate("gh", "a", {}).action == "allow"
    assert e.evaluate("gh", "a", {}).action == "allow"
    third = e.evaluate("gh", "a", {})
    assert (
        third.action == "deny" and third.rate_limited and "rate limit 2 calls per 10s" in (third.reason or "")
    )
    now[0] = 10.5
    assert e.evaluate("gh", "a", {}).action == "allow"
    assert e.evaluate("fs", "a", {}).action == "allow"  # other servers unaffected


def test_path_match_helper() -> None:
    assert path_match("a/b/c.py", "a/**")
    assert path_match("a/b.py", "a/*.py")
    assert not path_match("a/b/c.py", "a/*.py")


def test_hot_reload_swaps_valid_and_keeps_old_on_error(tmp_path: Path) -> None:
    p = tmp_path / "policy.yaml"
    p.write_text("version: 1\n")
    swaps: list[str] = []
    holder = PolicyHolder(PolicyFile(), p, on_swap=lambda eng, src: swaps.append(eng.hash))
    old = holder.hash

    p.write_text("rules:\n  - id: deny-all\n    action: deny\n")
    assert holder.reload() is True
    assert holder.hash != old and swaps == [holder.hash]
    assert holder.engine.evaluate("a", "b", {}).action == "deny"

    good = holder.hash
    p.write_text("rules:\n  - id: broken\n")  # invalid: no action
    assert holder.reload() is False
    assert holder.hash == good and "needs an 'action'" in (holder.last_error or "")


def test_poll_detects_mtime_change(tmp_path: Path) -> None:
    import os

    p = tmp_path / "policy.yaml"
    p.write_text("version: 1\n")
    holder = PolicyHolder(PolicyFile(), p)
    assert holder.poll() is False  # unchanged
    p.write_text("defaults: {action: deny}\n")
    os.utime(p, ns=(p.stat().st_atime_ns, p.stat().st_mtime_ns + 1_000_000))
    assert holder.poll() is True
    assert holder.policy.defaults.action == "deny"
