"""``shield`` command line: run the gateway, check config, export schemas, inspect the audit."""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Annotated

import anyio
import typer

from mcp_shield import __version__
from mcp_shield.config import ConfigError, json_schemas, load_config
from mcp_shield.metering.tokenizer import Tokenizer

app = typer.Typer(
    add_completion=False, no_args_is_help=True, help="MCP Shield: security gateway for MCP servers."
)

ConfigOpt = Annotated[Path, typer.Option("--config", "-c", help="Path to shield.yaml", exists=False)]


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out = {"level": record.levelname.lower(), "logger": record.name, "msg": record.getMessage()}
        if record.exc_info:
            out["exc"] = self.formatException(record.exc_info)
        return json.dumps(out)


def _setup_logging(level: str) -> None:
    # stdout carries the stdio MCP transport, so logs go to stderr only.
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_JsonFormatter())
    logging.basicConfig(level=level.upper(), handlers=[handler], force=True)


def _load(config: Path):  # type: ignore[no-untyped-def]
    try:
        return load_config(config)
    except ConfigError as e:
        typer.secho(str(e), fg="red", err=True)
        raise typer.Exit(2) from e


@app.command()
def run(
    config: ConfigOpt = Path("shield.yaml"),
    http: Annotated[bool, typer.Option("--http", help="Serve Streamable HTTP instead of stdio")] = False,
    host: Annotated[str, typer.Option(help="HTTP bind address")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="HTTP port")] = 8765,
    allow_host: Annotated[
        list[str] | None, typer.Option(help="Extra allowed Host header, e.g. shield:8765 (repeatable)")
    ] = None,
    log_level: Annotated[str, typer.Option(help="debug | info | warning")] = "info",
) -> None:
    """Run Shield over stdio (what MCP hosts launch) or, with --http, as a Streamable HTTP server."""
    _setup_logging(log_level)
    cfg = _load(config)
    from mcp_shield.app import Shield

    if not http:
        anyio.run(Shield.from_config(cfg).serve_stdio)
        return
    token = os.environ.get("SHIELD_TOKEN", "")
    if len(token) < 16:
        typer.secho("Set SHIELD_TOKEN (16+ characters) to run the HTTP server.", fg="red", err=True)
        raise typer.Exit(2)
    from mcp_shield.http_face import serve_http

    typer.secho(f"MCP Shield on http://{host}:{port}/mcp (bearer token required)", err=True)
    shield = Shield.from_config(cfg, connection_kind="http")
    anyio.run(lambda: serve_http(shield, token=token, host=host, port=port, extra_hosts=allow_host or []))


@app.command()
def dashboard(
    config: ConfigOpt = Path("shield.yaml"),
    db: Annotated[Path | None, typer.Option(help="Audit DB (overrides the config)")] = None,
    port: Annotated[int, typer.Option(help="Dashboard port")] = 8501,
    address: Annotated[
        str, typer.Option(help="Bind address (0.0.0.0 only inside a container)")
    ] = "127.0.0.1",
) -> None:
    """Open the read-only audit dashboard (Streamlit)."""
    import subprocess

    path = db if db is not None else _load(config).resolve(_load(config).shield.audit.db_path)
    app_file = Path(__file__).parent / "dashboard" / "app.py"
    env = {**os.environ, "SHIELD_DB": str(Path(path).resolve())}
    raise typer.Exit(
        subprocess.call(
            [
                sys.executable,
                "-m",
                "streamlit",
                "run",
                str(app_file),
                "--server.port",
                str(port),
                "--server.address",
                address,
                "--browser.gatherUsageStats",
                "false",
                "--server.headless",
                "true",
                "--theme.base",
                "light",
                "--theme.primaryColor",
                "#0f766e",
            ],
            env=env,
        )
    )


@app.command()
def export(
    config: ConfigOpt = Path("shield.yaml"),
    since: Annotated[str, typer.Option(help="15m | 1h | 24h | 7d | 30d | all")] = "24h",
    fmt: Annotated[str, typer.Option("--format", help="csv | json")] = "csv",
    out: Annotated[Path | None, typer.Option(help="Output file (default: stdout)")] = None,
    payloads: Annotated[bool, typer.Option(help="Include (redacted) payloads")] = False,
) -> None:
    """Export audit rows as evidence. Payloads are opt-in and always redacted."""
    from mcp_shield.audit.export import export_rows, to_csv, to_json
    from mcp_shield.audit.queries import Filters, since_iso
    from mcp_shield.audit.store import AuditStore

    cfg = _load(config)
    store = AuditStore(cfg.resolve(cfg.shield.audit.db_path), read_only=True)
    rows = export_rows(store, Filters(since=since_iso(since)), payloads=payloads)
    text = to_json(rows) if fmt == "json" else to_csv(rows)
    if out is None:
        typer.echo(text, nl=False)
    else:
        out.write_text(text)
        typer.echo(f"wrote {len(rows)} rows to {out}", err=True)


@app.command()
def prune(config: ConfigOpt = Path("shield.yaml")) -> None:
    """Apply audit retention now (delete rows older than audit.retention_days)."""
    from datetime import UTC, datetime, timedelta

    from mcp_shield.audit.store import AuditStore

    cfg = _load(config)
    days = cfg.shield.audit.retention_days
    cutoff = (datetime.now(UTC) - timedelta(days=days)).isoformat(timespec="milliseconds")
    n = AuditStore(cfg.resolve(cfg.shield.audit.db_path)).delete_older_than(cutoff)
    typer.echo(f"pruned {n} requests older than {days} days")


@app.command()
def check(config: ConfigOpt = Path("shield.yaml")) -> None:
    """Validate shield.yaml and the files it points to. Exit code 2 on errors."""
    cfg = _load(config)
    typer.secho(f"✓ {config} is valid", fg="green")
    typer.echo(f"  servers: {', '.join(s.id for s in cfg.servers.servers)}")
    typer.echo(f"  policy:  {len(cfg.policy.rules)} rules · hash {cfg.policy_hash}")
    typer.echo(f"  audit:   {cfg.resolve(cfg.shield.audit.db_path)}")


@app.command()
def schema(out: Annotated[Path, typer.Option(help="Directory for *.schema.json")] = Path("schemas")) -> None:
    """Write JSON Schemas for the config files (editor autocompletion)."""
    out.mkdir(parents=True, exist_ok=True)
    for name, s in json_schemas().items():
        (out / f"{name}.schema.json").write_text(json.dumps(s, indent=2))
    typer.echo(f"wrote {len(json_schemas())} schemas to {out}/")


@app.command()
def stats(
    config: ConfigOpt = Path("shield.yaml"),
    last: Annotated[int, typer.Option(help="Show the last N requests")] = 15,
) -> None:
    """Print a quick audit summary: totals, tokens per tool, latest requests."""
    from mcp_shield.audit.store import AuditStore

    cfg = _load(config)
    db = cfg.resolve(cfg.shield.audit.db_path)
    if not db.exists():
        typer.echo(f"No audit DB yet at {db}. Run `shield run` and make some calls first.")
        raise typer.Exit(0)
    store = AuditStore(db, read_only=True)
    total = store.query("""SELECT COUNT(*) n, COALESCE(SUM(t.total_tokens),0) tok, COALESCE(SUM(t.est_cost_usd),0) cost,
                           SUM(r.verdict IN ('block','denied','error')) blocked
                           FROM requests r JOIN token_usage t ON t.request_id = r.id""")[0]
    typer.secho(f"MCP Shield audit · {db}", bold=True)
    typer.echo(
        f"  requests {total['n']:,} · blocked/errors {total['blocked'] or 0:,} · "
        f"tokens {total['tok']:,} (estimated) · est. cost ${total['cost']:.4f}\n"
    )
    typer.secho("  Top tools by response tokens", bold=True)
    for r in store.query("""SELECT r.tool, COUNT(*) calls, SUM(t.response_tokens) resp, AVG(r.latency_ms) ms
                            FROM requests r JOIN token_usage t ON t.request_id=r.id
                            WHERE r.method='tools/call' GROUP BY r.tool ORDER BY resp DESC LIMIT 5"""):
        typer.echo(f"    {r['tool']:<32} {r['calls']:>5} calls  {r['resp']:>8,} tok  {r['ms']:>7.1f} ms avg")
    events = store.query("""SELECT f.rule_id, f.severity, COUNT(*) n, MAX(r.created_at) last
                            FROM findings f JOIN requests r ON r.id=f.request_id
                            WHERE f.severity IN ('medium','high','critical')
                            GROUP BY f.rule_id ORDER BY n DESC LIMIT 8""")
    if events:
        typer.secho("\n  Security events", bold=True)
        for e in events:
            colour = "red" if e["severity"] in ("high", "critical") else "yellow"
            typer.secho(f"    {e['severity']:<9}", fg=colour, nl=False)
            typer.echo(f" {e['rule_id']:<36} {e['n']:>4}×   last {e['last'][11:19]}")
    typer.secho(f"\n  Last {last} requests", bold=True)
    for r in store.query(
        """SELECT r.created_at, r.method, COALESCE(r.tool,'') tool, r.verdict,
                            t.total_tokens tok, r.latency_ms ms FROM requests r
                            JOIN token_usage t ON t.request_id=r.id ORDER BY r.created_at DESC LIMIT ?""",
        (last,),
    ):
        colour = {"allow": "green", "warn": "yellow"}.get(r["verdict"], "red")
        typer.echo(f"    {r['created_at'][11:23]}  {r['method']:<16} {r['tool']:<28} ", nl=False)
        typer.secho(f"{r['verdict']:<16}", fg=colour, nl=False)
        typer.echo(f" {r['tok']:>7,} tok {r['ms']:>8.1f} ms")


@app.command()
def calibrate(
    model: Annotated[
        str, typer.Option(help="Claude model whose tokenizer is the reference")
    ] = "claude-opus-5-5",
    encoding: Annotated[str, typer.Option(help="Offline tiktoken encoding to calibrate")] = "o200k_base",
) -> None:
    """Measure the offline estimate against Claude's count_tokens and print the scale factor (needs credentials)."""
    from mcp_shield.metering.calibrate import calibrate as run_calibration
    from mcp_shield.metering.tokenizer import AnthropicTokenizer, TiktokenTokenizer

    try:
        reference = _reference_tokenizer(model)
    except Exception as e:
        typer.secho(f"Cannot reach Claude's count_tokens: {e}", fg="red", err=True)
        typer.echo(
            "Install the extra (uv sync --extra claude) and sign in with `ant auth login`, "
            "or export ANTHROPIC_API_KEY.",
            err=True,
        )
        raise typer.Exit(2) from e
    report = run_calibration(reference, TiktokenTokenizer(encoding))
    if isinstance(reference, AnthropicTokenizer) and reference.fallbacks:
        typer.secho(
            f"{reference.fallbacks} count_tokens call(s) failed; the result is not valid.", fg="red", err=True
        )
        raise typer.Exit(1)
    typer.secho(f"Reference {report.reference} · estimator {report.estimator}", bold=True)
    typer.echo(f"{'sample':<16} {'claude':>8} {'estimate':>9} {'error':>8} {'scaled':>8} {'error':>8}")
    for s in report.samples:
        typer.echo(
            f"{s.label:<16} {s.reference:>8,} {s.estimate:>9,} {s.error_before:>+8.1%} "
            f"{s.scaled:>8,} {s.error_after:>+8.1%}"
        )
    typer.echo(
        f"\nworst error: {report.worst_before:.1%} unscaled → {report.worst_after:.1%} with scale {report.scale}"
    )
    ok = report.within_10pct
    typer.secho(
        f"{'✓' if ok else '✗'} PRD target ±10%: {'met' if ok else 'not met'}", fg="green" if ok else "red"
    )
    typer.echo(f"\nAdd to shield.yaml:\n  tokenizer:\n    kind: tiktoken\n    scale: {report.scale}")


def _reference_tokenizer(model: str) -> Tokenizer:
    from mcp_shield.metering.tokenizer import AnthropicTokenizer

    tok = AnthropicTokenizer(model)
    tok.overhead()  # one real call: fails fast without credentials
    return tok


@app.command()
def version() -> None:
    """Print the Shield version."""
    typer.echo(__version__)


if __name__ == "__main__":
    app()
