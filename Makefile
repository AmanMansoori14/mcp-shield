# MCP Shield developer tasks. Requires uv: https://docs.astral.sh/uv/
UV ?= uv
.PHONY: install check lint format typecheck test cov run http dashboard seed stats demo clean

install:            ## Create the venv and install dependencies
	$(UV) sync

check: lint typecheck test   ## Everything CI runs

lint:               ## Ruff lint + format check
	$(UV) run ruff check .
	$(UV) run ruff format --check .

format:             ## Auto-format
	$(UV) run ruff format .
	$(UV) run ruff check --fix .

typecheck:          ## mypy --strict on the package
	$(UV) run mypy

test:               ## Unit + integration tests (both MCP protocol revisions)
	$(UV) run pytest

cov:                ## Tests with coverage report (fails under 85%)
	$(UV) run pytest --cov --cov-report=term-missing --cov-fail-under=85

run:                ## Run Shield over stdio with the example config
	$(UV) run shield run --config examples/shield.yaml

http:               ## Run Shield as a Streamable HTTP server (needs SHIELD_TOKEN)
	$(UV) run shield run --http --config examples/shield.yaml

dashboard:          ## Open the audit dashboard for the example config
	$(UV) run shield dashboard --config examples/shield.yaml

seed:               ## Create a demo audit DB with 2,000 realistic calls, then open the dashboard on it
	rm -f demo-audit.db demo-audit.db-wal demo-audit.db-shm
	$(UV) run python -m demo.seed_audit demo-audit.db --calls 2000
	$(UV) run shield dashboard --db demo-audit.db

stats:              ## Summarise the example audit DB
	$(UV) run shield stats --config examples/shield.yaml

demo:               ## Drive Shield like an MCP client would, then print the audit
	$(UV) run python -m demo.drive examples/shield.yaml
	$(UV) run shield stats --config examples/shield.yaml

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage examples/shield-audit.db* examples/*.spool.jsonl demo-audit.db*
