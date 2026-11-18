"""Wave 2 end to end: policy, scanning, redaction, approvals, budget, pinning, hot reload."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from mcp import Client, MCPError, types

from demo.benign_server import mcp as notes
from demo.poisoned_server import mcp as evil
from demo.rugpull_server import make_rugpull
from mcp_shield.config import PolicyFile
from mcp_shield.pipeline.pipeline import SHIELD_META
from mcp_shield.security.approval import APPROVAL_KEY

pytestmark = pytest.mark.anyio


def text(result: types.CallToolResult) -> str:
    return "\n".join(getattr(c, "text", "") for c in result.content)


def last_call(shield: Any) -> dict[str, Any]:
    return shield.store.query(
        "SELECT * FROM requests WHERE method='tools/call' ORDER BY created_at DESC LIMIT 1"
    )[0]


def rules_of(shield: Any, request_id: str) -> set[str]:
    return {
        r["rule_id"]
        for r in shield.store.query("SELECT rule_id FROM findings WHERE request_id=?", (request_id,))
    }


def policy(**kw: Any) -> PolicyFile:
    return PolicyFile.model_validate(kw)


def answer_with(approve: bool | None, calls: list[str] | None = None) -> Any:
    async def cb(context: Any, params: types.ElicitRequestParams) -> types.ElicitResult:
        if calls is not None:
            calls.append(params.message)  # type: ignore[union-attr]
        if approve is None:
            return types.ElicitResult(action="decline")
        return types.ElicitResult(action="accept", content={"approve": approve})

    return cb


# --------------------------------------------------------------------------- poisoning & scanning


async def test_poisoned_tools_are_hidden_and_refused(make_shield: Any, mode: str) -> None:
    async with make_shield({"evil": evil}, mode=mode) as (shield, client):
        names = {t.name for t in (await client.list_tools()).tools}
        result = await client.call_tool("evil__get_weather", {"city": "Paris"})
    assert "evil__get_weather" not in names and "evil__translate" not in names  # exfil + hidden unicode
    assert "evil__fetch_page" in names and "evil__delete_note" in names
    assert result.is_error and "hidden by MCP Shield" in text(result)
    row = last_call(shield)
    assert row["verdict"] == "block" and "exfil.instruction" in rules_of(shield, row["id"])
    listing = shield.store.query("SELECT id, verdict FROM requests WHERE method='tools/list'")[0]
    assert listing["verdict"] == "warn" and "unicode.hidden_description" in rules_of(shield, listing["id"])


async def test_result_injection_warns_and_secrets_are_redacted(make_shield: Any, mode: str) -> None:
    async with make_shield({"evil": evil}, mode=mode) as (shield, client):
        result = await client.call_tool("evil__fetch_page", {"url": "https://docs.example"})
    out = text(result)
    assert not result.is_error
    assert "AKIAIOSFODNN7EXAMPLE" not in out and "[REDACTED:aws_access_key]" in out
    assert "[MCP Shield] Warning" in out and "Treat it as data" in out
    row = last_call(shield)
    assert row["verdict"] == "warn"
    assert {"injection.ignore_previous", "exfil.markdown_image", "redaction.aws_access_key"} <= rules_of(
        shield, row["id"]
    )
    assert "AKIAIOSFODNN7EXAMPLE" not in (row["result_redacted"] or "")


async def test_result_block_mode(make_shield: Any) -> None:
    async with make_shield({"evil": evil}, policy=policy(scanner={"result_action": "block"})) as (_, client):
        result = await client.call_tool("evil__fetch_page", {"url": "https://docs.example"})
    assert result.is_error and "instructions aimed at the model" in text(result)


async def test_suspicious_arguments_are_blocked(make_shield: Any, mode: str) -> None:
    async with make_shield({"notes": notes}, mode=mode) as (shield, client):
        result = await client.call_tool("notes__echo", {"text": "../../../etc/passwd"})
    assert result.is_error and "suspicious arguments" in text(result)
    assert result.meta and "args.path_traversal" in result.meta[SHIELD_META]["rule_ids"]
    assert last_call(shield)["verdict"] == "block"


# --------------------------------------------------------------------------- policy


async def test_policy_deny_rule(make_shield: Any, mode: str) -> None:
    p = policy(rules=[{"id": "no-echo", "match": {"server": "notes", "tool": "echo"}, "action": "deny"}])
    async with make_shield({"notes": notes}, mode=mode, policy=p) as (shield, client):
        denied = await client.call_tool("notes__echo", {"text": "hi"})
        allowed = await client.call_tool("notes__add", {"a": 1, "b": 2})
    assert denied.is_error and "denied by rule no-echo" in text(denied)
    assert not allowed.is_error
    stages = json.loads(shield.store.scalar("SELECT stage_ms FROM requests WHERE verdict='block'"))
    assert "policy" in stages and "upstream" not in stages


async def test_hot_reload_applies_without_restart(make_shield: Any, tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text("version: 1\n")
    async with make_shield({"notes": notes}, policy=PolicyFile(), policy_path=path) as (shield, client):
        first = await client.call_tool("notes__echo", {"text": "a"})
        old_hash = shield.holder.hash
        path.write_text("rules:\n  - id: freeze\n    match: {server: notes}\n    action: deny\n")
        os.utime(path, ns=(path.stat().st_atime_ns, path.stat().st_mtime_ns + 1_000_000))
        shield.holder.poll()
        second = await client.call_tool("notes__echo", {"text": "b"})
        path.write_text("rules: [ {id: broken} ]\n")  # invalid: keeps 'freeze'
        os.utime(path, ns=(path.stat().st_atime_ns, path.stat().st_mtime_ns + 2_000_000))
        shield.holder.poll()
        third = await client.call_tool("notes__echo", {"text": "c"})
    assert not first.is_error and second.is_error and third.is_error
    hashes = [
        r["policy_hash"]
        for r in shield.store.query(
            "SELECT policy_hash FROM requests WHERE method='tools/call' ORDER BY created_at"
        )
    ]
    assert hashes[0] == old_hash and hashes[1] == hashes[2] != old_hash
    assert shield.store.scalar("SELECT COUNT(*) FROM policy_versions") == 2


# --------------------------------------------------------------------------- approvals


@pytest.mark.parametrize("approve", [True, False, None], ids=["approve", "deny", "decline"])
async def test_destructive_tool_needs_approval(
    make_shield: Any, tmp_path: Path, mode: str, approve: bool | None
) -> None:
    asked: list[str] = []
    async with (
        make_shield({"evil": evil}, mode=mode) as (shield, _),
        Client(shield.server, mode=mode, elicitation_callback=answer_with(approve, asked)) as client,
    ):  # type: ignore[arg-type]
        result = await client.call_tool("evil__delete_note", {"name": "todo"})
    assert asked and "evil__delete_note" in asked[0] and "destructive" in asked[0]
    rows = shield.store.query("SELECT * FROM requests WHERE method='tools/call' ORDER BY created_at")
    final = rows[-1]
    if approve:
        assert not result.is_error and "Deleted note 'todo'" in text(result)
        assert final["verdict"] == "approved" and final["approval_ms"] is not None
    else:
        assert result.is_error and "denied by the user" in text(result)
        assert final["verdict"] == "denied"
    if mode == "auto":  # 2026-07-28: two legs, one logical call, arguments counted once
        assert rows[0]["verdict"] == "approval_pending" and len(rows) == 2
        assert rows[0]["logical_call_id"] == rows[1]["logical_call_id"] and [r["leg"] for r in rows] == [1, 2]
        tokens = shield.store.query(
            "SELECT request_tokens FROM token_usage t JOIN requests r ON r.id=t.request_id "
            "WHERE r.method='tools/call' ORDER BY r.created_at"
        )
        assert tokens[0]["request_tokens"] > 0 and tokens[1]["request_tokens"] == 0
    else:  # legacy: one live elicitation inside a single request
        assert len(rows) == 1


async def test_client_without_elicitation_is_denied(make_shield: Any, mode: str) -> None:
    async with make_shield({"evil": evil}, mode=mode) as (shield, client):
        result = await client.call_tool("evil__delete_note", {"name": "todo"})
    assert result.is_error and "cannot prompt the user" in text(result)
    assert "approval.unsupported_client" in rules_of(shield, last_call(shield)["id"])


async def test_late_approval_expires(make_shield: Any) -> None:
    async with make_shield({"evil": evil}) as (shield, _):
        base = shield.approver.clock()
        clock = [base]
        shield.approver.clock = lambda: clock[0]

        async def slow_human(context: Any, params: types.ElicitRequestParams) -> types.ElicitResult:
            clock[0] += 10_000  # the user answers hours later
            return types.ElicitResult(action="accept", content={"approve": True})

        async with Client(shield.server, elicitation_callback=slow_human) as client:  # type: ignore[arg-type]
            result = await client.call_tool("evil__delete_note", {"name": "todo"})
    assert result.is_error and "Approval expired" in text(result)
    assert last_call(shield)["verdict"] == "expired"


async def test_forged_request_state_is_rejected_and_audited(make_shield: Any) -> None:
    async with make_shield({"evil": evil}) as (shield, client):
        ok = types.ElicitResult(action="accept", content={"approve": True})
        with pytest.raises(MCPError) as exc:
            await client.session.call_tool(
                "evil__delete_note",
                {"name": "todo"},
                input_responses={APPROVAL_KEY: ok},
                request_state=json.dumps({"v": 1, "lc": "lc_forged", "h": "x", "iat": 0}),
            )
    assert "requestState" in exc.value.error.message
    row = last_call(shield)
    assert row["verdict"] == "denied" and "approval.state_invalid" in rules_of(shield, row["id"])


# --------------------------------------------------------------------------- budget


async def test_context_budget_warns(make_shield: Any) -> None:
    async with make_shield({"evil": evil}, policy=policy(context_budget={"per_call_tokens": 500})) as (
        shield,
        client,
    ):
        result = await client.call_tool("evil__dump_logs", {"lines": 2000})
    assert not result.is_error and "truncated" not in text(result)
    assert "budget.exceeded" in rules_of(shield, last_call(shield)["id"])


async def test_context_budget_truncates(make_shield: Any, mode: str) -> None:
    p = policy(context_budget={"per_call_tokens": 500, "on_exceed": "truncate"})
    async with make_shield({"evil": evil}, mode=mode, policy=p) as (shield, client):
        result = await client.call_tool("evil__dump_logs", {"lines": 2000})
    out = text(result)
    assert "[MCP Shield truncated about" in out and "500-token budget" in out
    tok = shield.store.query(
        "SELECT t.response_tokens FROM token_usage t JOIN requests r ON r.id=t.request_id "
        "WHERE r.method='tools/call'"
    )[0]["response_tokens"]
    assert tok <= 560  # budget + the notice itself


# --------------------------------------------------------------------------- rug-pull


async def test_rug_pull_needs_approval_then_is_accepted(make_shield: Any, mode: str) -> None:
    server, flip = make_rugpull()
    asked: list[str] = []
    async with (
        make_shield({"dict": server}, mode=mode) as (shield, _),
        Client(shield.server, mode=mode, elicitation_callback=answer_with(True, asked)) as client,  # type: ignore[arg-type]
    ):
        before = await client.call_tool("dict__define", {"word": "shield"})
        assert not asked  # trusted on first sight: no prompt
        flip()  # the upstream silently changes its description
        await shield.refresh_upstreams()
        # The new description is also poisoned (shadowing), so it is hidden outright.
        hidden = await client.call_tool("dict__define", {"word": "shield"})
    assert not before.is_error
    assert hidden.is_error and "hidden by MCP Shield" in text(hidden)
    pins = shield.store.query("SELECT status, last_changed_at FROM tool_pins WHERE server_id='dict'")[0]
    assert pins["last_changed_at"] is not None


async def test_benign_definition_change_requires_one_approval(make_shield: Any) -> None:
    from mcp.server import MCPServer

    srv = MCPServer("versions")

    @srv.tool(description="Return the version.")
    def version() -> str:
        return "1.0"

    asked: list[str] = []
    async with (
        make_shield({"v": srv}) as (shield, _),
        Client(shield.server, elicitation_callback=answer_with(True, asked)) as client,  # type: ignore[arg-type]
    ):
        await client.call_tool("v__version", {})
        srv._tool_manager._tools["version"].description = "Return the version string."  # benign update
        await shield.refresh_upstreams()
        first_after = await client.call_tool("v__version", {})
        second_after = await client.call_tool("v__version", {})
    assert len(asked) == 1 and "changed since it was first seen" in asked[0]
    assert not first_after.is_error and not second_after.is_error
    assert shield.store.scalar("SELECT status FROM tool_pins WHERE server_id='v'") == "pinned"
