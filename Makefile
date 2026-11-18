# MCP Shield developer tasks. Requires uv: https://docs.astral.sh/uv/
UV ?= uv
.PHONY: install check lint format typecheck test cov run http dashboard seed stats demo docker-demo calibrate gif clean

install:            ## Create the venv and install dependencies (with the optional Claude tokenizer)
	$(UV) sync --all-extras

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

docker-demo:        ## Build the image and run the attack walkthrough in containers (dashboard on 127.0.0.1:8501)
	docker compose up --build --exit-code-from demo demo
	@echo "Dashboard: docker compose up -d dashboard  ->  http://127.0.0.1:8501"

calibrate:          ## Measure tiktoken against Claude's tokenizer (needs ANTHROPIC_API_KEY or ant auth login)
	$(UV) run --extra claude shield calibrate

gif:                ## Re-record docs/assets/demo.gif from a fresh `make demo` run
	$(UV) run python scripts/make_demo_gif.py

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage examples/shield-audit.db* examples/*.spool.jsonl demo-audit.db*
