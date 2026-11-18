# Design Guideline — MCP Shield

This document turns the master plan into page-level UX for the audit dashboard. It also covers the copy users see inside the client, such as block messages and approval prompts. Read it after Gate 1, alongside the implementation and journey docs.

## Reference note

Reusable refs use the prefix `DG-<SectionLetter><Number>`. Page refs reuse the `P1`–`P6` IDs from MP Section 7.

## 1. Orientation and Intended Reader

- Intended readers: the implementer, coding agents, and reviewers.
- This file answers: how each dashboard page looks and behaves, and how Shield talks to users inside the MCP client.
- Read after: `master-plan.md`
- Read next: `user-journey.md`, `implementation-plan.md`, then `tasks.md`

## 2. Primary User Jobs by Page

| Page group | Primary user job | User mindset on arrival | Must be visible immediately | Mobile priority | Source refs |
|---|---|---|---|---|---|
| P1 Overview | Is everything healthy? What did it cost? | Quick check / demo | Requests, blocked %, total tokens, p95 latency, upstream health | Medium | MP-B7, J4 |
| P2 Request explorer | Find specific requests | Investigative | Filter bar + table (time, session, server, tool, verdict, tokens, latency) | Low | J4 |
| P3 Request detail | Understand one request fully | Forensic | Verdict badge, reason, token breakdown, findings, redacted payloads | Low | J3, J4 |
| P4 Token analytics | Where is context spent? | Optimizing | Tokens over time by server; top tools by response tokens; schema cost per server | Low | MP-B6, IP-B1 |
| P5 Security events | What was blocked/warned and why? | Urgent / reviewing | Event list grouped by rule, severity | Medium | J2, J5 |
| P6 Upstreams & policy | What is connected and which rules apply? | Setup / tuning | Server health, tool counts, hidden tools, active policy hash | Low | J1, J5 |

## 3. UI by Page Group

### Visual language baseline

| Axis | Current direction | Avoid | Growth direction |
|---|---|---|---|
| Typography | System sans for UI; `JetBrains Mono` for IDs, tool names, JSON | Mixed decorative fonts | Custom theme |
| Color and surfaces | Slate neutrals; teal accent; verdict colors: allow=green, warn=amber, block/denied=red, approved=blue, error=gray | Saturated backgrounds, color-only meaning | Dark theme |
| Spacing and density | Compact tables (32 px rows), 16 px gutters | Oversized cards | Saved views |
| Motion | Default Streamlit spinners only | Animated transitions | — |
| Iconography | Small shield, lock, and coin glyphs next to verdict, redaction, and token values | Stock illustrations | — |

#### P1 Overview

- **Purpose:** Answer "is it working and what is it costing?" in 5 seconds.
- **Primary actions:** Change the time range (15 min, 1 h, 24 h, 7 d) and click any KPI to drill down.
- **Attention order:** KPI row (requests · blocked % · total tokens · est. cost · p95 overhead), then a requests-over-time chart stacked by verdict, then the upstream health strip, then the last 10 security events.
- **Layout posture:** Dashboard, single column.
- **Failure state:** If there is no DB or no rows, show an empty state with the `shield run` command and the Claude Desktop config snippet.

#### P2 Request explorer

- **Purpose:** Find any request.
- **Filters:** Time range, connection, protocol version, server, tool, method, verdict, min tokens, and free text over the tool name and rule ID. All filters are reflected in the URL.
- **Columns:** time · connection (short) · protocol (`2026` / `legacy`) · method · `server__tool` · verdict badge · req tok · resp tok · total tok · latency. Sortable by tokens and latency. The two legs of an approved call are grouped under one expandable logical-call row.
- **Interaction:** Clicking a row opens P3. An export button downloads the current filter as CSV or JSON.
- **Failure state:** If the query is slow (more than 2 s), show the row count and suggest narrowing the time range.

#### P3 Request detail

- **Purpose:** Explain one decision completely.
- **Header:** Verdict badge, a plain-English reason ("Blocked by rule `deny-write-outside-sandbox`: path `/etc/passwd` is outside `./sandbox/**`"), request ID, logical call ID, connection, protocol version, and timestamp.
- **Tabs:**
  - **Summary:** latency breakdown (policy, upstream, scan, approval).
  - **Tokens:** request, response, schema and total as a bar, plus the tokenizer and an "estimated" label.
  - **Findings:** a table of rule, stage, severity and redacted excerpt.
  - **Payload:** collapsible JSON of the redacted params and result.
  - **Policy:** policy hash and matched rule YAML.
  - **Approval** (approved calls only): a two-step timeline (approval requested → user answered → retried and forwarded) with `approval_ms`, and how it was asked (multi-round-trip or legacy live elicitation).
- **Accessibility:** Verdict is always written as text next to its color.

#### P4 Token analytics

- **Purpose:** Find context bloat.
- **Charts:** Tokens over time stacked by server. Top 10 tools by average response tokens. Schema tokens per server, showing the standing cost of every tool definition. Calls that exceeded the context budget.
- **Interaction:** Clicking a bar opens P2 filtered to that server or tool.
- **Note:** A permanent caption reads "Token counts are estimates of MCP payloads entering model context (tokenizer: …)" (MP-C6).

#### P5 Security events

- **Purpose:** Review blocks and warnings.
- **Layout:** Grouped by rule, with count, last seen and severity. Expand a group to see requests, then open P3.
- **Failure state:** With no events, show "No security events in this range" and link to the demo fixtures.

#### P6 Upstreams & policy

- **Purpose:** Show what is connected and which rules apply.
- **Content:** One card per server (status, transport, tool count, schema tokens per turn, last error). A tool list with pin status (`pinned` / `changed` / `hidden`) and the date of the last definition change, plus a diff of the old and new description for changed tools. Dropped tools (invalid schema, or name too long) with the reason. Active policy YAML, read-only, with its hash and load time.

### In-client copy (DG-C1)

| Situation | Message shown to the model/user (JSON-RPC error message or result text) |
|---|---|
| Policy deny (tool result, `is_error: true`, so the model reads it) | `[MCP Shield] Blocked: tool fs__write_file denied by rule deny-write-outside-sandbox (path outside ./sandbox). Request ID r_8f2c.` |
| Approval prompt (approval request; the client renders it) | `MCP Shield: Allow github__merge_pull_request on repo "acme/api" PR #42? This action is marked as destructive.` with Approve and Deny buttons |
| Approval declined | `[MCP Shield] Denied by user. Request ID r_8f2c.` |
| Approval expired or tampered | `[MCP Shield] Approval expired (5 min) or invalid. Call the tool again to request a new approval. Request ID r_8f2c.` |
| Client can't show approvals | `[MCP Shield] Approval required, but this client cannot prompt the user. Ask an admin to relax rule approve-destructive or use a client with elicitation support.` |
| Tool definition changed (`on_change: require_approval`) | `MCP Shield: The definition of evil__get_weather changed since it was first seen. Allow this call?` |
| Upstream asked for sampling or elicitation | The upstream gets an error. The user sees nothing; the event is recorded in P5 (`passthrough.backchannel_refused`) |
| Redaction | Inline masks like `sk-…[REDACTED:api_key]`, with no extra banner |
| Budget exceeded (truncate mode) | `…[MCP Shield truncated 12,480 tokens; full result in audit r_8f2c]` |

## 4. Component Purpose Map

| Component or pattern | Purpose | Required states | Allowed variants | Avoid using it when | Source refs |
|---|---|---|---|---|---|
| KPI tile | Single metric + delta vs previous range | loading / value / empty | default, alert (amber) | Showing lists | P1 |
| Verdict badge | Verdict at a glance | allow / warn / block / approval_pending / approved / denied / expired / error | small, large | Decoration | MP-C2, MP-C4 |
| Data table | Explorer and event lists | loading / empty / rows / truncated | compact | Single request | P2, P5 |
| Token bar | Breakdown of request/response/schema | — | inline (table), large (P3) | — | IP-B1 |
| JSON viewer | Redacted payloads | collapsed / expanded / truncated | — | Unredacted data (never) | MP-C3 |
| Empty state | First-run guidance | — | with command snippet | — | P1 |

## 5. Wireframe Layout Sketches

### P1 Overview

```text
+--------------------------------------------------------------------+
| MCP Shield · Overview                     [15m][1h][24h][7d]  ⟳     |
+-----------+-----------+-------------+------------+-----------------+
| Requests  | Blocked % | Total tokens| Est. cost  | p95 overhead    |
| 1,284     | 2.1%      | 412k (est.) | $1.24      | 11 ms           |
+-----------+-----------+-------------+------------+-----------------+
| Requests over time (stacked: allow / warn / block)                  |
| ▁▂▃▅▃▂▆▇▅▃▂▁                                                         |
+--------------------------------------------------------------------+
| Upstreams:  ● fs (12 tools, 1.8k schema tok)  ● github  ✖ evil (3 hidden) |
+--------------------------------------------------------------------+
| Latest security events                                              |
| 14:02  BLOCK  evil__get_weather  description-injection.ignore-prev  |
| 13:58  WARN   fs__read_file      redaction.aws_key                  |
+--------------------------------------------------------------------+
```

### P3 Request detail

```text
+--------------------------------------------------------------------+
| ← Explorer   r_8f2c   [BLOCK]  fs__write_file   conn c_41a · 2026  14:02|
| Blocked by deny-write-outside-sandbox: path /etc/passwd not in glob |
+--------------------------------------------------------------------+
| [Summary] [Tokens] [Findings] [Payload] [Policy]                    |
| Tokens (estimated · tiktoken:o200k_base)                            |
|  request  ███ 38                                                    |
|  response ▏ 0 (blocked)                                             |
|  total    38      est. cost $0.0001                                 |
| Latency: policy 0.4 ms · scan 1.2 ms · upstream — · total 2.1 ms    |
+--------------------------------------------------------------------+
```

## 6. State Handling

| Page group | Loading state | Empty state | Validation state | System failure state | Recovery affordance |
|---|---|---|---|---|---|
| P1 | Skeleton tiles | First-run guide with commands | — | "Audit DB not found at …" | Show the configured path and `shield run` |
| P2 | Table spinner | "No requests match these filters" | Invalid date range is flagged inline | Query timeout message | Narrow range button |
| P3 | Spinner | "Request not found (may be past retention)" | — | — | Back to explorer |
| P4 | Chart placeholders | "No token data yet" | — | Tokenizer fallback banner (char/4 in use) | Link to config docs |
| P5 | Spinner | "No security events" | — | — | Link to demo fixtures |
| P6 | Spinner | "No upstreams configured" | Policy YAML error with line number | Upstream down card (red) with last error | Restart hint |

## 7. Open UX Questions and Follow-up Links

| Topic | Question or risk | Why it matters | Linked refs | Next move |
|---|---|---|---|---|
| Hidden tools | Should poisoned tools be hidden or shown with a warning prefix? | Transparency vs safety | IP-A3, UJ-C2 | Default hide; config `description_action: warn` |
| Cost display | Show cost when no pricing is configured? | Avoid fake precision | MP-C6 | Hide cost tile unless `pricing.yaml` exists |
| Grouped connections | 2026-07-28 HTTP traffic has no session; grouping is a heuristic | Users may think grouped rows are exact | MP-C (Connection) | Label `grouped` connections with a tooltip explaining the heuristic |

### Gate 2 contribution check

- [x] Every page group has a happy path and failure posture.
- [x] The visual direction is concrete.
- [x] Component and state rules match the page inventory.
- [x] Links to journey and implementation docs are explicit.
