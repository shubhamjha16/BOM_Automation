# BOM Factory

CERT-In conformance and attestation platform. Ingests a supplier's Bill of
Materials submission, scores **all five BOM types in parallel** against the
CERT-In minimum elements, correlates them against each other, and issues a
clause-referenced conformance assessment.

Source of truth for every clause reference: *CERT-In Technical Guidelines on
SBOM, QBOM & CBOM, AIBOM and HBOM*, **v2.0, 09.07.2025**. The full specification
and the 21-sprint plan are in [`BOM_FACTORY_SPRINTS.md`](BOM_FACTORY_SPRINTS.md).

## What this is, and is not

**A conformance engine that is never an LLM.** Field-level scoring is
deterministic table lookup and coverage arithmetic. The model writes commentary
about verdicts; it never produces a verdict, a percentage or a clause reference.

**Not a sixth SBOM generator.** Syft, Trivy and cdxgen are mature and free. The
scarce work is scoring what suppliers actually send you against the 21 fields,
clause by clause, and saying plainly which gaps are the supplier's and which are
yours.

## Quick start

```bash
make install                     # uv sync + yarn install
cp backend/.env.example backend/.env.local     # fill in the three required keys
make dev                         # postgres + redis + API + Vite
```

`make dev` needs Docker for Postgres and Redis. Without it, `make dev-api` and
`make dev-web` run each app on its own — S1 needs no database.

| Command | What it does |
|---|---|
| `make test` | pytest + vitest |
| `make lint` | ruff + eslint |
| `make self-bom` | CycloneDX SBOM of this repo into `dist/` |
| `make help` | every target |

## Current state — S1–S2 complete

The parallel graph, in the target structure, with two lanes scoring:

```
intake → detect → fanout ─┬→ sbomLane  ─┐
                          ├→ cbomLane  ─┤
                          ├→ qbomLane  ─┼→ join → correlate → conformanceGate
                          ├→ aibomLane ─┤
                          └→ hbomLane  ─┘
```

- **SBOM** (s.4.2, 21 elements) and **AIBOM** (s.9.3, 16 elements) score against
  encoded catalogues. CBOM, QBOM and HBOM nodes exist and report `lane_absent`
  until S14/S16 — their catalogues are deliberately **empty rather than
  approximated**, because a guessed table produces a score against invented
  clauses.
- All five lanes run on every assessment, concurrently, with independent failure
  and timeout. `GET /api/v1/elements?lane=sbom` returns the encoded catalogue so
  it can be checked against the published PDF rather than trusted.
- This repo generates and scores **its own SBOM**: currently **38.28%, fail**,
  855 components — see below.

**S2 adds Postgres and Alembic, and there is no `jobs.json`.** A job is a row:
`orgs`, `users`, `clients`, `engagements`, `jobs`, `node_runs`, with the first
migration hand-written and hand-reviewed per §5.

- **Terminal finality** is a conditional `UPDATE ... WHERE terminal_at IS NULL`,
  not a read-then-write. A read-then-write races: a lane finishing as a timeout
  handler fires gives two writers who both see `None`, and the loser overwrites a
  terminal verdict. It matters most for `blocked_conformance` — a late write-back
  flipping it to `succeeded` would make an assessment the gate refused to issue
  become issuable.
- **Tenancy is enforced at the repository layer.** A repository cannot be
  constructed without an org scope and every query it builds carries it. Reads
  for another tenant return nothing rather than an error, so existence does not
  leak.
- **A crash leaves a reconcilable row**, because the row is written before the
  work starts. Orphans are marked `failed`, never silently requeued — whether a
  re-run is safe depends on what the job already wrote.

**Not yet built** (and not claimed): no queue (S4), no auth (S5), no SPDX parsing
(S6), no enrichment, identifier mapping or VEX (S10–S12).

### Testing the database layer without a database

The models are deliberately dialect-portable, so repository logic runs on SQLite
via `aiosqlite` and the guards are exercised on every push. The migration is
validated by rendering it through Alembic's **offline mode** and diffing the
result against the model metadata — schema drift is caught in CI with no Postgres
at all.

What that cannot cover is stated at the foot of `tests/test_repositories.py`:
real `text[]`/`JSONB`/native enums, the genuinely partial index, and concurrent
writers actually racing the guard. `alembic upgrade head`, `downgrade -1` and the
round-trip need a live Postgres and are the deferred exit proofs.

### On parallelism, measured rather than assumed

The five lanes genuinely overlap in wall-clock time, and `AssessmentSummary.
parallelism_proven` asserts it from the `node_runs` intervals. But scoring is
pure Python and holds the GIL, so **concurrency here buys isolation, not
throughput** — 4,000 components + 3,000 models took 173 ms and 124 ms alone,
263 ms back to back, 281 ms through the fan-out.

That is the right trade and it is recorded in `graph/laneRunner.py` rather than
left to be discovered under load at S21. What the fan-out is actually for is that
a hung or crashed lane cannot take the others with it. Throughput arrives when
lanes stop being pure CPU: S10's enrichment is network-bound and releases the
GIL. If CPU-bound scoring later needs real parallelism, the change is one call
site — the lane bodies are already pure and synchronous.

### We ship what we ask for

`make self-bom` runs cdxgen over this repository and `app.services.self.selfScore`
scores the result with this repository's engine:

```
self-conformance: 38.28% (fail) over 855 components
  fails on critical gap(s): 4.2(4) Supplier Name, 4.2(21) CERT-In Unique Identifier
```

That number is low and it is published anyway. 4.2(21) cannot pass before S11
builds the supplier registry, and the enrichment fields cannot pass before S10.
S13 turns this into a CI gate at `SELF_CONFORMANCE_MIN`; gating now would only
prove that unimplemented sprints score badly.

## The rules that are not preferences

Read §11 of the specification before changing `services/score/`,
`services/catalogue/` or `validators/`.

- **`not_determinable` is never `compliant`.** Criticality (4.2(12)), Usage
  Restrictions (4.2(13)) and AIBOM's Intended and Out-of-Scope Usage
  (9.3(15)–(16)) cannot be established from a BOM artifact. They leave the
  supplier score entirely and render in their own section with the consumer
  action required.
- **Partial coverage is not a pass.** Licences on 12 of 400 components scores 3%
  on 4.2(5).
- **Nothing is dropped silently.** parsed + rejected equals the input entry count,
  asserted per document.
- **An unrecognised format raises.** It never returns an empty component list,
  because an empty list renders a green assessment.
- **`lane_not_applicable` ≠ `lane_absent`.** The first is excluded from the
  overall score; the second is a finding.
- **A critical gap fails regardless of score.** A BOM with no versions can score
  respectably on descriptive fields while being useless.

## Layout

```
backend/          FastAPI + LangGraph      mirrors ai-chat-be
frontend/         Vite + React 19 + TS     mirrors etl-student-frontend
packages/         generated API types (S3)
dist/             our own SBOM/AIBOM/CBOM per release
```

## Provenance of the encoded catalogue

Eight SBOM clause ordinals and three AIBOM ones are anchored by the
specification and asserted in `tests/test_catalogue.py`. **The rest are encoded
from the tables and marked provisional** until an assessor re-derives them from
the published PDF — that is the S20 catalogue audit, and it is a gate. One wrong
clause discredits every assessment issued.
