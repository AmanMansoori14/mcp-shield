"""Typed configuration for MCP Shield (TS-A2).

Three YAML files, each validated by a Pydantic model:

* ``shield.yaml``  - process settings (audit DB, tokenizer, pricing, paths to the other two files)
* ``servers.yaml`` - upstream MCP servers (MP-B1)
* ``policy.yaml``  - security policy (MP-B2; enforced from wave 2, validated now)

Errors carry the file and line number of the offending YAML node, and ``${VAR}`` /
``${VAR:-default}`` references are expanded from the environment before validation.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")
SERVER_ID = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")


class ConfigError(Exception):
    """A configuration problem, reported as ``file:line: message`` lines."""

    def __init__(self, path: Path | str, problems: list[tuple[int | None, str]]):
        self.path = str(path)
        self.problems = problems
        lines = [f"{self.path}:{line}: {msg}" if line else f"{self.path}: {msg}" for line, msg in problems]
        super().__init__("\n".join(lines))


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


# --------------------------------------------------------------------------- servers.yaml


class StdioServer(_Strict):
    id: str
    transport: Literal["stdio"]
    command: list[str] = Field(min_length=1)
    env: dict[str, str] = Field(default_factory=dict)
    cwd: str | None = None
    timeout_s: float = Field(default=30.0, gt=0, le=600)

    @field_validator("id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _check_id(v)


class HttpServer(_Strict):
    id: str
    transport: Literal["http"]
    url: str = Field(pattern=r"^https?://")
    headers: dict[str, str] = Field(default_factory=dict)
    timeout_s: float = Field(default=30.0, gt=0, le=600)

    @field_validator("id")
    @classmethod
    def _id(cls, v: str) -> str:
        return _check_id(v)


ServerConfig = Annotated[StdioServer | HttpServer, Field(discriminator="transport")]


def _check_id(v: str) -> str:
    if not SERVER_ID.match(v):
        raise ValueError(
            "server id must be lowercase letters, digits, '_' or '-', start with a letter, max 32"
        )
    if "__" in v:
        raise ValueError("server id must not contain '__' (reserved as the tool prefix separator)")
    return v


class ServersFile(_Strict):
    servers: list[ServerConfig] = Field(min_length=1)

    @model_validator(mode="after")
    def _unique_ids(self) -> ServersFile:
        seen: set[str] = set()
        for s in self.servers:
            if s.id in seen:
                raise ValueError(f"duplicate server id {s.id!r}")
            seen.add(s.id)
        return self


# --------------------------------------------------------------------------- policy.yaml


class PolicyDefaults(_Strict):
    action: Literal["allow", "deny"] = "allow"
    fail_open: bool = False


class ClassifierSettings(_Strict):
    enabled: bool = False
    threshold: float = Field(default=0.85, gt=0, le=1)


class ScannerSettings(_Strict):
    """What to do when the injection scanner fires (MP-B3)."""

    description_action: Literal["warn", "block"] = "block"  # block = hide the tool
    result_action: Literal["off", "warn", "block"] = "warn"
    args_action: Literal["off", "warn", "block"] = "block"
    classifier: ClassifierSettings = Field(default_factory=ClassifierSettings)


class ContextBudget(_Strict):
    per_call_tokens: int = Field(default=4000, gt=0)
    on_exceed: Literal["warn", "truncate"] = "warn"


class ApprovalSettings(_Strict):
    token_ttl_s: int = Field(default=300, gt=0, le=3600)
    approve_destructive: bool = True


class PinningSettings(_Strict):
    on_change: Literal["warn", "block", "require_approval"] = "require_approval"


class RuleMatch(_Strict):
    server: str | list[str] | None = None
    tool: str | list[str] | None = None


class RuleWhen(_Strict):
    arg: str
    glob: str | None = None
    not_glob: str | None = None
    regex: str | None = None


class RateLimit(_Strict):
    calls: int = Field(gt=0)
    per_s: float = Field(gt=0)


class PolicyRule(_Strict):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]*$")
    match: RuleMatch = Field(default_factory=RuleMatch)
    when: RuleWhen | None = None
    action: Literal["allow", "deny", "require_approval"] | None = None
    rate_limit: RateLimit | None = None

    @model_validator(mode="after")
    def _has_effect(self) -> PolicyRule:
        if self.action is None and self.rate_limit is None:
            raise ValueError(f"rule {self.id!r} needs an 'action' or a 'rate_limit'")
        return self


class PolicyFile(_Strict):
    version: Literal[1] = 1
    defaults: PolicyDefaults = Field(default_factory=PolicyDefaults)
    context_budget: ContextBudget = Field(default_factory=ContextBudget)
    approval: ApprovalSettings = Field(default_factory=ApprovalSettings)
    pinning: PinningSettings = Field(default_factory=PinningSettings)
    scanner: ScannerSettings = Field(default_factory=ScannerSettings)
    rules: list[PolicyRule] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_rule_ids(self) -> PolicyFile:
        ids = [r.id for r in self.rules]
        dupes = {i for i in ids if ids.count(i) > 1}
        if dupes:
            raise ValueError(f"duplicate rule ids: {sorted(dupes)}")
        return self


# --------------------------------------------------------------------------- shield.yaml


class TokenizerSettings(_Strict):
    kind: Literal["tiktoken", "char"] = "tiktoken"
    encoding: str = "o200k_base"
    image_tokens: int = Field(default=1500, ge=0)
    offload_bytes: int = Field(default=32_768, gt=0)


class AuditSettings(_Strict):
    db_path: str = "shield-audit.db"
    spool_path: str = "shield-audit.spool.jsonl"
    queue_size: int = Field(default=10_000, gt=0)
    max_payload_bytes: int = Field(default=65_536, gt=0)
    retention_days: int = Field(default=30, gt=0)
    store_payloads: bool = True  # always redacted first (MP-C3)


class ShieldFile(_Strict):
    servers: str = "servers.yaml"
    policy: str | None = "policy.yaml"
    pricing: str | None = None
    audit: AuditSettings = Field(default_factory=AuditSettings)
    tokenizer: TokenizerSettings = Field(default_factory=TokenizerSettings)
    refresh_interval_s: float = Field(default=30.0, ge=1)  # re-list upstreams (rug-pull detection)
    audit_tools: bool = True  # expose read-only shield_* tools to the agent
    policy_reload_interval_s: float = Field(default=1.0, gt=0)


class PricingFile(_Strict):
    """Input-token price used for the *estimated* cost column (MP-C6)."""

    currency: Literal["USD"] = "USD"
    input_per_million: float = Field(ge=0)


# --------------------------------------------------------------------------- loaded bundle


class LoadedConfig(BaseModel):
    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    shield: ShieldFile
    servers: ServersFile
    policy: PolicyFile
    pricing: PricingFile | None
    policy_hash: str
    policy_source: str | None
    base_dir: Path

    def resolve(self, relative: str) -> Path:
        p = Path(relative)
        return p if p.is_absolute() else self.base_dir / p


def load_yaml_model[M: BaseModel](path: Path, model: type[M], env: dict[str, str] | None = None) -> M:
    """Parse ``path`` into ``model`` with env expansion and line-numbered errors."""
    env = dict(os.environ) if env is None else env
    try:
        text = path.read_text()
    except OSError as e:
        raise ConfigError(path, [(None, f"cannot read file: {e.strerror}")]) from e
    try:
        root = yaml.compose(text)
    except yaml.YAMLError as e:
        mark = getattr(e, "problem_mark", None)
        raise ConfigError(path, [(mark.line + 1 if mark else None, f"invalid YAML: {e}")]) from e
    if root is None:
        raise ConfigError(path, [(None, "file is empty")])

    problems: list[tuple[int | None, str]] = []
    data = _to_python(root, env, problems)
    if problems:
        raise ConfigError(path, problems)
    try:
        return model.model_validate(data)
    except ValidationError as e:
        for err in e.errors():
            loc = tuple(err["loc"])
            node = _node_at(root, loc)
            where = ".".join(str(p) for p in loc) or "(root)"
            problems.append((node.start_mark.line + 1 if node else None, f"{where}: {err['msg']}"))
        raise ConfigError(path, problems) from e


def load_config(shield_path: Path | str, env: dict[str, str] | None = None) -> LoadedConfig:
    """Load ``shield.yaml`` and the servers/policy/pricing files it points to."""
    shield_path = Path(shield_path)
    base = shield_path.parent
    shield = load_yaml_model(shield_path, ShieldFile, env)
    servers = load_yaml_model(_rel(base, shield.servers), ServersFile, env)
    if shield.policy:
        policy_path = _rel(base, shield.policy)
        policy = load_yaml_model(policy_path, PolicyFile, env)
        policy_source: str | None = policy_path.read_text()
    else:
        policy, policy_source = PolicyFile(), None
    pricing = load_yaml_model(_rel(base, shield.pricing), PricingFile, env) if shield.pricing else None
    return LoadedConfig(
        shield=shield,
        servers=servers,
        policy=policy,
        pricing=pricing,
        policy_hash=policy_hash(policy),
        policy_source=policy_source,
        base_dir=base,
    )


def policy_hash(policy: PolicyFile) -> str:
    """Stable short hash of the *effective* policy (MP-C4): formatting changes don't change it."""
    canonical = json.dumps(policy.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return "p_" + hashlib.sha256(canonical.encode()).hexdigest()[:12]


def json_schemas() -> dict[str, dict[str, Any]]:
    """JSON Schemas for editor autocompletion (``shield schema``)."""
    return {
        "shield": ShieldFile.model_json_schema(),
        "servers": ServersFile.model_json_schema(),
        "policy": PolicyFile.model_json_schema(),
        "pricing": PricingFile.model_json_schema(),
    }


# --------------------------------------------------------------------------- helpers


def _rel(base: Path, p: str) -> Path:
    path = Path(p)
    return path if path.is_absolute() else base / path


def _to_python(node: yaml.Node, env: dict[str, str], problems: list[tuple[int | None, str]]) -> Any:
    if isinstance(node, yaml.MappingNode):
        return {_to_python(k, env, problems): _to_python(v, env, problems) for k, v in node.value}
    if isinstance(node, yaml.SequenceNode):
        return [_to_python(v, env, problems) for v in node.value]
    assert isinstance(node, yaml.ScalarNode)
    value = yaml.safe_load(yaml.serialize(node)) if node.tag != "tag:yaml.org,2002:str" else node.value
    if isinstance(value, str):
        value = _expand_env(value, env, node.start_mark.line + 1, problems)
    return value


def _expand_env(value: str, env: dict[str, str], line: int, problems: list[tuple[int | None, str]]) -> str:
    def sub(m: re.Match[str]) -> str:
        name, default = m.group(1), m.group(2)
        if name in env:
            return env[name]
        if default is not None:
            return default
        problems.append((line, f"environment variable ${{{name}}} is not set"))
        return ""

    return _ENV_REF.sub(sub, value)


def _node_at(root: yaml.Node, loc: tuple[Any, ...]) -> yaml.Node | None:
    """Walk the YAML node tree along a Pydantic error location; return the deepest match."""
    node: yaml.Node = root
    for part in loc:
        if isinstance(node, yaml.MappingNode) and isinstance(part, str):
            nxt = next((v for k, v in node.value if getattr(k, "value", None) == part), None)
            if nxt is None:
                # Discriminated unions add the tag ("stdio") to the loc: skip it.
                continue
            node = nxt
        elif isinstance(node, yaml.SequenceNode) and isinstance(part, int) and part < len(node.value):
            node = node.value[part]
        else:
            continue
    return node
