"""``shield`` command line: run the gateway, check config, export schemas, inspect the audit."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Annotated

import anyio
import typer

from mcp_shield import __version__
from mcp_shield.config import ConfigError, json_schemas, load_config

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
    log_level: Annotated[str, typer.Option(help="debug | info | warning")] = "info",
) -> None:
    """Run Shield over stdio (point Claude Desktop / Claude Code at this command)."""
    _setup_logging(log_level)
    cfg = _load(config)
    from mcp_shield.app import Shield

    anyio.run(Shield.from_config(cfg).serve_stdio)


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
    typer.secho(f"\n  Last {last} requests", bold=True)
    for r in store.query(
        """SELECT r.created_at, r.method, COALESCE(r.tool,'') tool, r.verdict,
                            t.total_tokens tok, r.latency_ms ms FROM requests r
                            JOIN token_usage t ON t.request_id=r.id ORDER BY r.created_at DESC LIMIT ?""",
        (last,),
    ):
        colour = {"allow": "green", "warn": "yellow"}.get(r["verdict"], "red")
        typer.echo(f"    {r['created_at'][11:23]}  {r['method']:<16} {r['tool']:<28} ", nl=False)
        typer.secho(f"{r['verdict']:<8}", fg=colour, nl=False)
        typer.echo(f" {r['tok']:>7,} tok {r['ms']:>8.1f} ms")


@app.command()
def version() -> None:
    """Print the Shield version."""
    typer.echo(__version__)


if __name__ == "__main__":
    app()
