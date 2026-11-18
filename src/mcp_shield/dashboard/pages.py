"""MCP Shield audit dashboard (TS-C1..C4, design guideline P1-P6). Read-only.

shield dashboard -c shield.yaml          # or: SHIELD_DB=path streamlit run app.py
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from mcp_shield.audit import queries as q
from mcp_shield.audit.export import export_rows, to_csv, to_json
from mcp_shield.audit.store import AuditStore

# Reference palette (dataviz skill, validated): categorical slots in fixed order, status colors reserved.
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]
STATUS = {"good": "#0ca30c", "warning": "#fab219", "serious": "#ec835a", "critical": "#d03b3b"}
VERDICT_STATUS = {
    "allow": "good",
    "approved": "good",
    "warn": "warning",
    "approval_pending": "serious",
    "expired": "serious",
    "block": "critical",
    "denied": "critical",
    "error": "critical",
}
VERDICT_ICON = {"good": "✓", "warning": "▲", "serious": "◆", "critical": "✕"}
VERDICT_ORDER = ["allow", "approved", "warn", "approval_pending", "expired", "denied", "block", "error"]
SURFACE, INK, MUTED, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e7e6e1"


def setup() -> None:
    st.set_page_config(page_title="MCP Shield", page_icon="🛡️", layout="wide")
    st.markdown(
        """<style>
        .block-container {padding-top: 1.6rem;}
        code, .mono {font-family: "JetBrains Mono", Menlo, monospace; font-size: 0.85em;}
        .badge {display:inline-block;padding:1px 9px;border-radius:10px;font-size:0.8em;font-weight:600;
                border:1px solid currentColor;}
        </style>""",
        unsafe_allow_html=True,
    )


@st.cache_resource
def store() -> AuditStore | None:
    path = os.environ.get("SHIELD_DB", "shield-audit.db")
    return AuditStore(path, read_only=True) if Path(path).exists() else None


def badge(verdict: str) -> str:
    status = VERDICT_STATUS.get(verdict, "critical")
    return (
        f'<span class="badge" style="color:{STATUS[status]}">{VERDICT_ICON[status]} '
        f'<span style="color:{INK}">{verdict}</span></span>'
    )


def server_colors(s: AuditStore) -> dict[str, str]:
    """Color follows the entity: slots assigned by sorted server id, so filters never repaint."""
    ids = sorted({r["server_id"] for r in q.upstreams(s)} | {"shield"})
    return {sid: SERIES[i] if i < len(SERIES) else "#8a8984" for i, sid in enumerate(ids)}


def style(fig: go.Figure, height: int = 300, bargap: float = 0.25) -> go.Figure:
    fig.update_layout(
        height=height,
        margin={"l": 8, "r": 8, "t": 8, "b": 8},
        paper_bgcolor=SURFACE,
        plot_bgcolor=SURFACE,
        font={"color": INK, "size": 12},
        legend={"orientation": "h", "y": 1.02, "yanchor": "bottom", "x": 0, "font": {"color": MUTED}},
        barmode="stack",
        bargap=bargap,
        hovermode="x unified",
    )
    fig.update_xaxes(showgrid=False, linecolor=GRID, tickfont={"color": MUTED})
    fig.update_yaxes(gridcolor=GRID, zeroline=False, tickfont={"color": MUTED})
    fig.update_traces(marker_line_color=SURFACE, marker_line_width=2, selector={"type": "bar"})
    return fig


def range_picker(key: str = "range") -> tuple[str, str | None]:
    """Time range in the URL (?range=24h) so a reviewer can share the exact view."""
    choice = (
        st.segmented_control(
            "Time range",
            list(q.RANGES),
            default=st.query_params.get("range", "24h"),
            key=key,
            label_visibility="collapsed",
        )
        or "24h"
    )
    if st.query_params.get("range") != choice:  # only write on change: avoids needless reruns
        st.query_params["range"] = choice
    return choice, q.since_iso(choice)


BUCKET = {"15m": "minute", "1h": "minute", "24h": "hour", "7d": "hour"}


def empty_state() -> None:
    st.info("No audit data yet. Start Shield and make a few calls:")
    st.code(
        "uv run shield run --config examples/shield.yaml\nuv run python -m demo.drive examples/shield.yaml",
        language="bash",
    )


# --------------------------------------------------------------------------- P1 Overview


def page_overview() -> None:
    s = store()
    st.title("Overview")
    if s is None:
        st.error(f"Audit DB not found at `{os.environ.get('SHIELD_DB', 'shield-audit.db')}`.")
        return empty_state()
    choice, since = range_picker()
    o = q.overview(s, since)
    if not o["requests"]:
        return empty_state()
    c = st.columns(5)
    c[0].metric("Requests", f"{o['requests']:,}")
    c[1].metric(
        "Blocked / errors",
        f"{o['blocked_pct']}%",
        help=f"{o['blocked']:,} requests blocked, denied, expired or failed",
    )
    c[2].metric("Tokens (estimated)", f"{o['total_tokens']:,}")
    c[3].metric("Est. cost", f"${o['est_cost_usd']:.4f}" if o["est_cost_usd"] is not None else "–")
    c[4].metric("p95 Shield overhead", f"{o['p95_overhead_ms']} ms")

    rows = pd.DataFrame(q.timeseries(s, since, BUCKET.get(choice, "day")))
    st.subheader("Requests over time", divider="gray")
    # One bar segment per status (allowed / warned / pending / blocked): four reserved colors, four labels.
    groups = {
        "allowed": ["allow", "approved"],
        "warned": ["warn"],
        "pending or expired": ["approval_pending", "expired"],
        "blocked or failed": ["block", "denied", "error"],
    }
    fig = go.Figure()
    for label, verdicts in groups.items():
        part = rows[rows.verdict.isin(verdicts)].groupby("bucket", as_index=False)["requests"].sum()
        if len(part):
            fig.add_bar(
                x=part.bucket,
                y=part.requests,
                name=label,
                marker_color=STATUS[VERDICT_STATUS[verdicts[0]]],
                hovertemplate=f"{label}: %{{y:,}}<extra></extra>",
            )
    st.plotly_chart(style(fig), width="stretch")

    left, right = st.columns([3, 2])
    with left:
        st.subheader("Upstreams", divider="gray")
        for u in q.upstreams(s):
            status = {"up": "good", "degraded": "warning", "down": "critical"}[u["status"]]
            st.markdown(
                f'<span class="badge" style="color:{STATUS[status]}">{VERDICT_ICON[status]} '
                f'<span style="color:{INK}">{u["status"]}</span></span> &nbsp;**{u["server_id"]}** · '
                f"{u['tool_count']} tool{'' if u['tool_count'] == 1 else 's'} · {u['schema_tokens']:,} schema tokens/turn"
                + (
                    f' · <span style="color:{MUTED}">{len(u["dropped_tools"])} dropped</span>'
                    if u["dropped_tools"]
                    else ""
                ),
                unsafe_allow_html=True,
            )
    with right:
        st.subheader("Latest security events", divider="gray")
        for e in q.security_events(s, since, "high", 6):
            st.markdown(f"`{e['last_seen'][11:19]}` **{e['rule_id']}** · {e['count']}× · {e['severity']}")


# --------------------------------------------------------------------------- P2/P3 Requests


def page_requests() -> None:
    s = store()
    st.title("Requests")
    if s is None:
        return empty_state()
    if rid := st.query_params.get("id"):
        return request_detail(s, rid)
    _, since = range_picker()
    f1, f2, f3, f4 = st.columns([2, 2, 3, 2])
    servers = ["(any)", *sorted(u["server_id"] for u in q.upstreams(s)), "shield"]
    server = f1.selectbox("Server", servers, key="server")
    verdicts = f2.multiselect("Verdict", VERDICT_ORDER, key="verdicts")
    text = f3.text_input("Search tool, rule or request id", key="text")
    order = f4.selectbox("Sort", ["newest", "tokens", "latency"], key="order")
    filters = q.Filters(
        since=since,
        server_id=None if server == "(any)" else server,
        verdicts=verdicts,
        text=text or None,
        order=order,
        limit=200,
    )
    rows, total = q.list_requests(s, filters)
    st.caption(f"{total:,} requests · showing {len(rows)} · tokens are estimates")
    if not rows:
        st.info("No requests match these filters.")
        return
    df = pd.DataFrame(rows)
    df["status"] = df.verdict.map(lambda v: f"{VERDICT_ICON[VERDICT_STATUS.get(v, 'critical')]} {v}")
    df["time"] = df.created_at.str.slice(11, 23)
    view = df[
        [
            "time",
            "status",
            "method",
            "tool",
            "request_tokens",
            "response_tokens",
            "total_tokens",
            "latency_ms",
            "protocol_version",
            "id",
        ]
    ]
    picked = st.dataframe(
        view,
        hide_index=True,
        width="stretch",
        on_select="rerun",
        selection_mode="single-row",
        column_config={
            "total_tokens": st.column_config.ProgressColumn(
                "total tokens", format="%d", max_value=int(df.total_tokens.max() or 1)
            ),
            "latency_ms": st.column_config.NumberColumn("latency ms", format="%.1f"),
            "id": st.column_config.TextColumn("request id"),
        },
    )
    if picked.selection.rows:
        st.query_params["id"] = view.iloc[picked.selection.rows[0]]["id"]
        st.rerun()
    left, right = st.columns([1, 4])
    fmt = left.radio("Export format", ["csv", "json"], horizontal=True, key="fmt")
    if right.button("Prepare export of this view"):  # built on demand, not on every rerun
        data = export_rows(s, filters)
        st.session_state["export"] = (fmt, to_csv(data) if fmt == "csv" else to_json(data), len(data))
    if "export" in st.session_state:
        efmt, payload, n = st.session_state["export"]
        right.download_button(f"Download {n:,} rows ({efmt})", payload, file_name=f"shield-audit.{efmt}")


def request_detail(s: AuditStore, rid: str) -> None:
    r = q.get_request(s, rid)
    if st.button("← Back to requests"):
        del st.query_params["id"]
        st.rerun()
    if r is None:
        st.warning("Request not found (it may be past retention).")
        return
    st.markdown(
        f"### {badge(r['verdict'])} &nbsp;<code>{r['tool'] or r['method']}</code>", unsafe_allow_html=True
    )
    if r["error_message"]:
        st.markdown(f"**Reason:** {r['error_message']}")
    st.caption(
        f"request `{r['id']}` · logical call `{r['logical_call_id']}` · connection `{r['connection_id']}` · "
        f"protocol {r['protocol_version']} · {r['created_at']}"
    )
    t_sum, t_tok, t_find, t_pay, t_pol, t_app = st.tabs(
        ["Summary", "Tokens", "Findings", "Payload", "Policy", "Approval"]
    )
    with t_sum:
        stages = pd.DataFrame([{"stage": k, "ms": v} for k, v in r["stage_ms"].items()])
        c = st.columns(3)
        c[0].metric("Total latency", f"{r['latency_ms']:.1f} ms")
        c[1].metric("Upstream", f"{r['upstream_ms']:.1f} ms" if r["upstream_ms"] is not None else "–")
        c[2].metric(
            "Shield overhead", f"{r['latency_ms'] - (r['upstream_ms'] or 0) - (r['approval_ms'] or 0):.1f} ms"
        )
        if len(stages):
            st.plotly_chart(
                style(
                    go.Figure(
                        go.Bar(
                            x=stages.ms,
                            y=stages.stage,
                            orientation="h",
                            marker_color=SERIES[0],
                            hovertemplate="%{y}: %{x:.2f} ms<extra></extra>",
                        )
                    ),
                    220,
                ),
                width="stretch",
            )
    with t_tok:
        st.caption(f"Estimated with `{r['tokenizer']}` (MCP payloads entering model context)")
        cols = st.columns(4)
        for col, k in zip(
            cols, ["request_tokens", "response_tokens", "schema_tokens", "total_tokens"], strict=True
        ):
            col.metric(k.replace("_", " "), f"{r[k]:,}")
        if r["est_cost_usd"] is not None:
            st.caption(f"Estimated cost ${r['est_cost_usd']:.6f}")
    with t_find:
        if r["findings"]:
            st.dataframe(pd.DataFrame(r["findings"]), hide_index=True, width="stretch")
        else:
            st.write("No findings.")
    with t_pay:
        st.caption(
            "Redacted before storage. Truncated at 64 KB."
            + (" (truncated)" if r["payload_truncated"] else "")
        )
        for label, key in (("Params", "params_redacted"), ("Result", "result_redacted")):
            with st.expander(label, expanded=False):
                st.json(json.loads(r[key]) if r[key] else {})
    with t_pol:
        st.markdown(f"Policy `{r['policy_hash']}` · Shield {r['shield_version']}")
        if r["policy"] and r["policy"]["yaml_source"]:
            st.code(r["policy"]["yaml_source"], language="yaml")
    with t_app:
        if len(r["legs"]) > 1 or r["approval_ms"] is not None:
            for leg in r["legs"]:
                st.markdown(
                    f"Leg {leg['leg']} · {badge(leg['verdict'])} · `{leg['created_at'][11:23]}`",
                    unsafe_allow_html=True,
                )
            if r["approval_ms"] is not None:
                st.caption(f"Time to answer: {r['approval_ms'] / 1000:.1f} s")
        else:
            st.write("No approval was needed for this call.")


# --------------------------------------------------------------------------- P4 Tokens


def page_tokens() -> None:
    s = store()
    st.title("Token analytics")
    st.caption("Token counts are estimates of MCP payloads entering model context.")
    if s is None:
        return empty_state()
    choice, since = range_picker()
    colors = server_colors(s)
    ts = pd.DataFrame(q.timeseries(s, since, BUCKET.get(choice, "day")))
    st.subheader("Tokens over time, by server", divider="gray")
    if len(ts):
        fig = go.Figure()
        for sid, color in colors.items():
            part = ts[ts.server_id == sid].groupby("bucket", as_index=False)["tokens"].sum()
            if len(part):
                fig.add_bar(
                    x=part.bucket,
                    y=part.tokens,
                    name=sid,
                    marker_color=color,
                    hovertemplate=f"{sid}: %{{y:,}} tokens<extra></extra>",
                )
        st.plotly_chart(style(fig), width="stretch")
    left, right = st.columns(2)
    with left:
        st.subheader("Top tools by response tokens", divider="gray")
        top = pd.DataFrame(q.token_usage(s, since, "tool", 10))
        if len(top):
            top = top.sort_values("response_tokens")
            fig = go.Figure(
                go.Bar(
                    x=top.response_tokens,
                    y=top.key,
                    orientation="h",
                    marker_color=[colors.get(str(k).split("__", 1)[0], MUTED) for k in top.key],
                    customdata=top[["calls", "avg_response_tokens"]],
                    hovertemplate="%{y}<br>%{x:,} tokens · %{customdata[0]} calls · "
                    "avg %{customdata[1]:,}<extra></extra>",
                )
            )
            st.plotly_chart(style(fig, 340, bargap=0.45), width="stretch")
    with right:
        st.subheader("Tool-definition cost per turn", divider="gray")
        ups = pd.DataFrame(q.upstreams(s))
        if len(ups):
            ups = ups.sort_values("schema_tokens")
            fig = go.Figure(
                go.Bar(
                    x=ups.schema_tokens,
                    y=ups.server_id,
                    orientation="h",
                    marker_color=[colors.get(x, SERIES[0]) for x in ups.server_id],
                    hovertemplate="%{y}: %{x:,} tokens every model turn<extra></extra>",
                )
            )
            st.plotly_chart(style(fig, 340, bargap=0.45), width="stretch")
    st.subheader("Context-budget breaches", divider="gray")
    breaches = q.budget_breaches(s, since)
    if breaches:
        st.dataframe(pd.DataFrame(breaches), hide_index=True, width="stretch")
    else:
        st.write("No calls exceeded the context budget.")


# --------------------------------------------------------------------------- P5 Security


def page_security() -> None:
    s = store()
    st.title("Security events")
    if s is None:
        return empty_state()
    _, since = range_picker()
    sev = st.select_slider("Minimum severity", list(q.SEVERITY_RANK), value="medium")
    events = q.security_events(s, since, sev, 100)
    if not events:
        st.success("No security events in this range.")
        return
    df = pd.DataFrame(events)
    status = {
        "critical": "critical",
        "high": "critical",
        "medium": "serious",
        "low": "warning",
        "info": "good",
    }
    df["severity"] = df.severity.map(lambda v: f"{VERDICT_ICON[status[v]]} {v}")
    st.dataframe(
        df[
            ["severity", "rule_id", "stage", "count", "tools", "first_seen", "last_seen", "latest_request_id"]
        ],
        hide_index=True,
        width="stretch",
    )
    st.caption("Open a request: Requests page → search for its id.")


# --------------------------------------------------------------------------- P6 Upstreams & policy


def page_upstreams() -> None:
    s = store()
    st.title("Upstreams & policy")
    if s is None:
        return empty_state()
    st.subheader("Servers", divider="gray")
    st.dataframe(pd.DataFrame(q.upstreams(s)), hide_index=True, width="stretch")
    st.subheader("Tool pins", divider="gray")
    pins = pd.DataFrame(q.tool_pins(s))
    if len(pins):
        icons = {"pinned": "✓ pinned", "changed": "◆ changed", "hidden": "✕ hidden"}
        pins["status"] = pins.status.map(icons)
        pins["def_hash"] = pins.def_hash.str.slice(0, 12)
        st.dataframe(pins, hide_index=True, width="stretch")
    st.subheader("Active policy", divider="gray")
    p = q.current_policy(s)
    if p:
        st.caption(f"`{p['hash']}` loaded {p['loaded_at']}")
        st.code(p["yaml_source"] or "(defaults)", language="yaml")


def main() -> None:
    setup()
    nav = st.navigation(
        [
            st.Page(page_overview, title="Overview", icon="🛡️", default=True),
            st.Page(page_requests, title="Requests", icon="📜", url_path="requests"),
            st.Page(page_tokens, title="Token analytics", icon="🪙", url_path="tokens"),
            st.Page(page_security, title="Security events", icon="🚨", url_path="security"),
            st.Page(page_upstreams, title="Upstreams & policy", icon="🔌", url_path="upstreams"),
        ]
    )
    nav.run()
