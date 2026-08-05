# BOM Factory — one entrypoint for both apps.
# Every target is safe to run from a clean checkout.

SHELL := /bin/bash
BACKEND := backend
FRONTEND := frontend
COMPOSE := $(shell command -v docker >/dev/null 2>&1 && echo "docker compose" || echo "")

.DEFAULT_GOAL := help
.PHONY: help install install-backend install-frontend infra infra-down dev dev-api dev-web \
        test test-backend test-frontend lint fmt typecheck migrate revision self-bom \
        catalogue-audit scale clean \
        docker-build docker-up docker-down docker-logs docker-config api-types api-types-check \
        seed-catalogue demo demo-seed demo-api demo-web demo-reset

help: ## Show available targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

install: install-backend install-frontend ## Install both apps' dependencies

install-backend: ## uv sync the backend (fetches Python 3.12 if absent)
	cd $(BACKEND) && uv sync --all-extras

install-frontend: ## yarn install the workspace root + frontend
	yarn install

infra: ## Start postgres + redis
ifeq ($(COMPOSE),)
	@echo "docker not found — start postgres:16 on 5432 and redis on 6379 yourself,"
	@echo "or install Docker Desktop and re-run 'make infra'."
	@exit 1
else
	$(COMPOSE) up -d postgres redis
	@echo "waiting for postgres..."
	@until $(COMPOSE) exec -T postgres pg_isready -U bom -q; do sleep 1; done
	@echo "infra up: postgres :5432  redis :6379"
endif

infra-down: ## Stop infra containers
	$(COMPOSE) down

dev: infra ## Bring up postgres, redis, the API and Vite (one command)
	@trap 'kill 0' EXIT INT TERM; \
	$(MAKE) dev-api & \
	$(MAKE) dev-web & \
	wait

dev-api: ## Run the FastAPI app with reload
	cd $(BACKEND) && uv run uvicorn app.main:app --reload --port $${PORT:-8005}

dev-web: ## Run the Vite dev server
	cd $(FRONTEND) && yarn dev

test: test-backend test-frontend ## Run both test suites

test-backend: ## pytest
	cd $(BACKEND) && uv run pytest -q

test-frontend: ## vitest
	cd $(FRONTEND) && yarn test --run

lint: ## ruff + eslint
	cd $(BACKEND) && uv run ruff check app tests
	cd $(FRONTEND) && yarn lint

fmt: ## ruff format
	cd $(BACKEND) && uv run ruff format app tests

typecheck: ## mypy + tsc
	cd $(BACKEND) && uv run mypy app
	cd $(FRONTEND) && yarn typecheck

migrate: ## alembic upgrade head (S2)
	cd $(BACKEND) && uv run alembic upgrade head

# --- demo: the whole stack on SQLite, no Docker ------------------------------
# The models are dialect-portable (that is why the repository guards are testable
# without a live database), so a demo needs no Postgres and no Redis. Production
# is Postgres; this is a demo path, not a supported deployment.

DEMO_ENV := DATABASE_URL=sqlite+aiosqlite:///./demo.db JOBS_INLINE=true MFA_REQUIRED=false

demo: ## Seed and run the whole stack on SQLite, then open the console
	@$(MAKE) demo-seed
	@trap 'kill 0' EXIT INT TERM; \
	$(MAKE) demo-api & \
	$(MAKE) demo-web & \
	echo ""; \
	echo "  console  http://localhost:5173"; \
	echo "  api      http://localhost:8005/docs"; \
	echo ""; \
	wait

demo-seed: ## Create demo.db with a catalogue, an account and a real BOM
	cd $(BACKEND) && $(DEMO_ENV) uv run python -m app.scripts.seedDemo

demo-api: ## Run the API against the demo database
	cd $(BACKEND) && $(DEMO_ENV) uv run uvicorn app.main:app --port 8005

demo-web: ## Run the console against the demo API
	cd $(FRONTEND) && yarn dev

demo-reset: ## Delete the demo database
	rm -f $(BACKEND)/demo.db && echo "demo.db removed"

seed-catalogue: ## Seed the minimum-element catalogue (deployment step, after migrate)
	cd $(BACKEND) && uv run python -m app.scripts.seedCatalogue

revision: ## alembic revision --autogenerate -m "$(M)" (hand-review it; see §5)
	cd $(BACKEND) && uv run alembic revision --autogenerate -m "$(M)"

api-types: ## Regenerate packages/api-types from the backend OpenAPI schema
	cd $(BACKEND) && uv run python -m app.scripts.dumpOpenapi ../packages/api-types/openapi.json
	yarn workspace @bom-factory/api-types generate

api-types-check: api-types ## Fail if the generated types are stale (CI gate)
	@git diff --exit-code -- packages/api-types \
	  || (echo ""; \
	      echo "packages/api-types is stale. The backend schema changed without"; \
	      echo "regenerating the TypeScript. Run 'make api-types' and commit."; \
	      exit 1)

scale: ## Measure a 50,000-component SBOM and per-lane p95 (S21)
	@cd $(BACKEND) && ENRICHMENT_ONLINE=false uv run python -m app.scripts.scaleProfile

catalogue-audit: ## Worksheet of every clause reference, with its provenance (S20)
	@cd backend && uv run python -m app.services.catalogue.audit

self-bom: ## Emit a CycloneDX SBOM for this repository into dist/ (rec. 7.2.2)
	@mkdir -p dist
	yarn --silent self-bom
	@node -e "const b=require('./dist/bom-factory.cdx.json');console.log('self-bom: '+b.bomFormat+' '+b.specVersion+', '+(b.components||[]).length+' components -> dist/bom-factory.cdx.json')"

# --- containerised stack (the `full` compose profile) ------------------------
# `make dev` stays the recommended dev loop; these are for running the whole
# stack the way it deploys.

docker-config: ## Validate the compose file without building anything
	$(COMPOSE) --profile full config --quiet && echo "compose config valid"

docker-build: ## Build the api, worker and console images
	$(COMPOSE) --profile full build

docker-up: ## Run the whole stack: postgres, redis, api, worker, console
	$(COMPOSE) --profile full up -d
	@echo "api     http://localhost:8005/api/v1/health"
	@echo "console http://localhost:8080"

docker-down: ## Stop the whole stack (add ARGS=-v to drop the volumes too)
	$(COMPOSE) --profile full down $(ARGS)

docker-logs: ## Tail logs from the app services
	$(COMPOSE) --profile full logs -f api worker web

clean: ## Remove build and cache artifacts
	rm -rf $(FRONTEND)/dist $(FRONTEND)/node_modules node_modules $(BACKEND)/.venv \
	       $(BACKEND)/.pytest_cache $(BACKEND)/.ruff_cache $(BACKEND)/.mypy_cache
