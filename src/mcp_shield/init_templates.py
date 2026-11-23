"""Starter config written by ``shield init`` (gap #15, UJ-C1 step 2).

One real upstream (the reference filesystem server, rooted at ./sandbox) and a policy that
keeps writes inside it and asks before destructive tools. Paths are relative to shield.yaml.
"""

from __future__ import annotations

SHIELD_YAML = """\
# MCP Shield process settings. Paths are relative to this file.
servers: servers.yaml
policy: policy.yaml
# pricing: pricing.yaml   # optional: input-token price for the estimated-cost column

audit_tools: true        # expose read-only shield_* tools to the agent
refresh_interval_s: 30   # re-list upstreams to catch changed tool definitions (rug pulls)

audit:
  db_path: shield-audit.db
  retention_days: 30

tokenizer:
  kind: tiktoken          # tiktoken | char | anthropic (exact Claude counts, needs credentials)
  encoding: o200k_base
  # scale: 1.18           # from `shield calibrate`: corrects tiktoken towards Claude's tokenizer
"""

SERVERS_YAML = """\
# Upstream MCP servers. The id becomes the tool prefix: fs__read_file, fs__write_file, ...
servers:
  - id: fs
    transport: stdio
    command: ["npx", "-y", "@modelcontextprotocol/server-filesystem", "./sandbox"]
    timeout_s: 30

  # More examples (uncomment to use):
  # - id: github
  #   transport: http
  #   url: https://example.internal/mcp
  #   headers: { Authorization: "Bearer ${GITHUB_MCP_TOKEN}" }   # the upstream's own token
"""

POLICY_YAML = """\
# Security policy. Edits are hot-reloaded; an invalid file keeps the previous policy.
# Dry-run it any time: shield check-policy policy.yaml
version: 1
defaults: { action: allow }   # internal errors always block (fail-closed)
context_budget: { per_call_tokens: 4000, on_exceed: warn }
approval: { token_ttl_s: 300, approve_destructive: true }
pinning: { on_change: require_approval }
scanner: { description_action: block, result_action: warn, args_action: block }

rules:
  - id: deny-write-outside-sandbox
    match: { server: fs, tool: write_file }
    when: { arg: path, not_glob: "./sandbox/**" }
    action: deny
  - id: approve-destructive
    match: { tool: ["delete_*", "*_merge", "drop_*", "move_file"] }
    action: require_approval
  - id: rate-limit-github
    match: { server: github }
    rate_limit: { calls: 30, per_s: 60 }
"""

FILES: dict[str, str] = {
    "shield.yaml": SHIELD_YAML,
    "servers.yaml": SERVERS_YAML,
    "policy.yaml": POLICY_YAML,
}
