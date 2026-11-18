# MCP Shield developer tasks. Requires uv: https://docs.astral.sh/uv/
UV ?= uv
.PHONY: install check lint format typecheck test cov run stats demo clean

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

cov:                ## Tests with coverage report
	$(UV) run pytest --cov --cov-report=term-missing

run:                ## Run Shield over stdio with the example config
	$(UV) run shield run --config examples/shield.yaml

stats:              ## Summarise the example audit DB
	$(UV) run shield stats --config examples/shield.yaml

demo:               ## Drive Shield like an MCP client would, then print the audit
	$(UV) run python -m demo.drive examples/shield.yaml
	$(UV) run shield stats --config examples/shield.yaml

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage examples/shield-audit.db* examples/*.spool.jsonl
