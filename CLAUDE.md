# BOM Factory — working agreement

CERT-In conformance and attestation platform. One repository, two apps: `backend/`
(FastAPI, mirrors `ai-chat-be`) and `frontend/` (Vite + React 19, mirrors
`etl-student-frontend`). Source of truth for every clause reference is
*CERT-In Technical Guidelines on SBOM, QBOM & CBOM, AIBOM and HBOM*, **v2.0, 09.07.2025**.

The full specification and the 21-sprint plan live in `BOM_FACTORY_SPRINTS.md`.
Read §11 before changing anything in `services/score/`, `services/catalogue/` or
`validators/` — those rules are the product, not preferences.

## Non-negotiable rules

- **The LLM never produces a verdict, a figure or a clause reference.** Those come
  from `services/score/` and `services/catalogue/`. Anything else in rendered output
  is a blocking error, enforced in code, not by prompt instruction.
- **`not_determinable` is never `compliant`.** Excluded from the supplier score,
  reported in its own section, paired with the consumer action required.
- **Nothing is dropped silently.** parsed + rejected must equal input entry count.
- **Partial coverage is not a pass.** Licences on 12 of 400 components has not met 4.2(5).
- **Lanes fail independently.** An absent or timed-out lane is a reported finding,
  never a crashed assessment.
- **`lane_not_applicable` ≠ `lane_absent`.** The first is excluded from the overall
  score; the second is a finding.
- **Agents research; they never decide.** Every agentic output is a proposal carrying
  evidence, confidence and hop count, queued for human confirmation.
- **Tenancy is enforced at the repository layer**, never the router.
- **We ship what we ask for.** This repo publishes its own SBOM/AIBOM/CBOM per release,
  scored by its own engine.

## Layout rules

- `backend/app` carries the same nine directories as `ai-chat-be`: `configs`,
  `controllers`, `models`, `repositories`, `routers`, `schemas`, `services`, `utils`,
  `validators` (plus `workers`). **`repositories` is spelled correctly here** — the
  sibling repo's `respositories` typo is not carried over (§13.4).
- `frontend/src` carries `components`, `features`, `global`, `hooks`, `layouts`,
  `router`, `shared/constants`, `store`, `utils`. Features are self-contained:
  `components/ hooks/ services/ store.ts types.ts index.ts`.
- **No module in `services/graph/` exceeds 200 lines**, and `builder.py` contains
  zero prompt text. Prompts are data, one module per node, under `graph/prompts/`.
- Route handlers stay under 15 lines and contain no SQL.

## Commands

```
make install     # uv sync + yarn install
make dev         # postgres + redis + API + Vite, one command
make test        # pytest + vitest
make lint        # ruff + eslint
make self-bom    # CycloneDX SBOM of this repo into dist/
```

## Conventions

- Config is `pydantic-settings` and **fails at import** on a missing required var,
  naming it. Never `os.environ.get(..., "")`.
- Async everywhere in the backend; no `threading.Thread`, no `jobs.json`.
- Filenames in `backend/app` are camelCase to match the house repos; Python symbols
  inside them are snake_case.
