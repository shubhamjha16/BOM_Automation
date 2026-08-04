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

## Current state — S1–S13 complete · the console is clickable

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

**S3 adds the layered HTTP surface and generated API types.**
`routers/` → `controllers/` → `services/` → `repositories/`, enforced by tests:
route handlers stay under 15 lines and an AST check fails the build if a router
or controller builds a query. Repositories own SQL, so an endpoint cannot
accidentally add one that forgets its org scope.

- **A submission with zero documents returns 422**, naming rec. 7.1.2 — never an
  assessment. Every violation is reported at once rather than one per round trip.
- **An oversized body is refused at the edge.** Pure-ASGI middleware checks
  `Content-Length` before touching the body and also counts bytes as they stream,
  because `Content-Length` is a claim the client can omit or lie about. A 300 MB
  document returns 413 having been read zero times.
- **`packages/api-types` is generated from the OpenAPI schema** and consumed by
  the console. `make api-types-check` regenerates and diffs: a backend schema
  change without regenerated types exits non-zero in CI.

**S4 puts assessments on a real queue.** arq + Redis, a separate worker process,
no `threading.Thread` anywhere. `POST /submissions/{id}/commit` returns a job,
not an assessment — waiting would tie a 50,000-component scoring run to an HTTP
timeout.

- **Idempotency**: SHA-256 over org id, sorted document checksums and sorted
  enabled lanes. Order-independent, tenant-separated (two clients submitting the
  same public SBOM must not collide), and lane-set-aware. The same documents
  twice returns one `job_id` and executes once.
- **The whole fan-out is one task**, not five. Five tasks would need a barrier to
  know when to join, and a barrier over a queue is a distributed lock — the graph
  already gives an in-process join. The queue provides concurrency across
  *submissions*, which is where it is actually needed.
- Redelivery is safe because terminal finality (S2) makes a settled job immutable.

**S5 adds authentication and closes tenancy.** JWT with typed tokens, Argon2id
passwords, TOTP MFA on by default, and five roles.

- **MFA is a step, not a flag.** A correct password yields only a five-minute
  `mfa_pending` token that can read nothing; the access token is minted after the
  code verifies. Token *kind* is checked on every request, so a refresh token
  cannot be presented as an access token.
- **Sign-in failures are indistinguishable.** An unknown email is verified
  against a dummy hash so response time does not reveal which addresses exist.
- **Tenancy is enforced in the repository layer**, and a test parses the AST to
  fail the build if any repository does not inherit `TenantScopedRepository`.
  Cross-tenant reads return **404, byte-identical to a nonexistent id** — proven
  across all four access paths: read, list, search and download.
- Route guards in the console hide what a user cannot use. They are **not** access
  control, and say so: the server enforces the same rules whether or not they ran.

**S6 closes ingestion.** SPDX 2.2/2.3 in both JSON and tag-value, alongside
CycloneDX 1.4–1.6, all behind one dispatcher.

- **Format detection is explicit and caller-overridable, never guessed.** The
  caller declares the format and the document must agree; a contradiction raises.
  A mis-detected document yields zero components, and zero components scores as a
  clean assessment of a supplier who submitted nothing wrong.
- **parsed + rejected == received, asserted per document across every fixture.**
  A silent drop shrinks the denominator and therefore *raises* every coverage
  percentage — silent drops don't just lose information, they inflate the score.
- **A truncated tag-value document fails naming the byte offset.** Tag-value has
  no closing delimiter, so a file cut mid-transfer stays syntactically valid and
  simply contains fewer packages than were sent.
- `GET /submissions/{id}/rejected` lists every dropped entry with a reason, plus
  the counts so a reader can check the arithmetic themselves.
- `NOASSERTION`/`NONE` are treated as absences, because SPDX mandates them where
  a producer has no data.

**S7 makes the catalogue versioned data.** `guideline_versions` and
`minimum_elements` are seeded from the encoded catalogue and checksummed; every
lane result is pinned to the version it was scored under.

- **Editing a version's elements in place is refused.** A catalogue change means
  a new version row, because otherwise every assessment already issued under v2.0
  silently starts reporting against different rules.
- **Seeding is a deployment step** (`make seed-catalogue`), beside
  `alembic upgrade head` — never on the assessment path.
- `tests/vectors/` holds hand-scored BOMs matched **field by field**, not on the
  total: two compensating errors give the right percentage from the wrong
  verdicts.

**S8 is the blocking gate, and it has no bypass flag.** Nothing renders unless
every clause it would cite resolves in the pinned guideline version — field
verdicts and correlation findings alike. A fabricated reference terminates the
job as `blocked_conformance` naming the field.

There is no parameter, environment variable or override that skips it. A flag
would be used, eventually, by someone under deadline, and the assessment it let
through would carry a citation that resolves to nothing. Two tests enforce this
structurally: the gate takes `state` and nothing else, and imports no settings.

The determinability rule is enforced at the gate too, not merely in the scorer:
a `not_determinable` field carrying coverage, a consumer determination given a
supplier verdict, or one rendered without its consumer action all block.

**S9 correlates across lanes** — the class of finding no single-lane tool can
produce, because each rule compares one document's declarations against
another's.

| Rule | Clause | Finding |
|---|---|---|
| `cryptoInSbom` | s.8.4.1.2 | OpenSSL in the SBOM, no cryptographic assets declared anywhere |
| `modelDepsInSbom` | s.9.3(6) | AIBOM declares `torch`, the SBOM does not carry it — the SBOM is incomplete |
| `algorithmQuantumExposure` | s.8.5.1 | CBOM declares RSA, no post-quantum migration entry |
| `firmwareInHbom` | s.10.2.4 | pending the HBOM lane (S16) |
| `vexCoverage` | rec. 7.1.6 | pending enrichment (S10) and VEX (S12) |

**A rule whose inputs are absent does not fire.** A submission carrying only an
SBOM has not failed to declare its cryptography — it was never asked to, and
firing anyway would manufacture findings about documents nobody submitted. Rules
that could not run are reported as skipped, because "found nothing" and "did not
run" are different answers.

**S10 enriches the four fields no generator emits.** NVD, CISA KEV and
endoflife.date are wired and verified against the live services — Python 3.8 →
EOL 2024-10-07, Django 3.2 → 2024-04-01, log4shell CVSS 10.0 and KEV-listed.

- **Provenance is recorded on every enriched value.** 4.2(8)–4.2(11) are fields
  the *supplier* was required to declare; when we fill one from NVD the
  assessment says so, or a reader concludes the supplier declared it.
- **A feed that is down is a reported gap**, never an empty vulnerability list —
  an empty list is the claim "we checked and there is nothing".
- The bounded agent handles only what the feeds miss: plan → retrieve →
  sufficiency → re-query, capped at `AGENT_MAX_HOPS`, **batched per distinct
  product**. An exhausted budget reports unresolved, never a plausible date.

**S11 builds the CERT-In identifier.** Table 3's worked example converts exactly:

```
pkg:maven/org.apache.tomcat/tomcat-catalina@9.0.71
  -> pkg:supplier/ApacheSoftwareFoundation/tomcat-catalina@9.0.71
```

`supplier` is not a registered PURL type, which is why no generator emits it and
why 4.2(21) is absent on every real BOM until a registry exists. Resolution runs
a deterministic ladder — curated (1.0) → declared supplier (0.8) → PURL namespace
(0.5) → unresolved (0.0) — and **an unresolvable component reports absent rather
than emitting a plausible-looking wrong identifier**.

The sufficiency check is the point: `azer` (a real npm publisher) and
`com.github.someone` are **refused**, because a username must not become a
CERT-In supplier identifier. The agent proposes; a human confirms; confirmation
permanently improves the curated asset.

**S12 is VEX, and the agent never decides.** The four statuses of rec. 7.1.6 are
exhaustive — `mitigated` is rejected naming all four — and `not_affected` cannot
be saved without a written justification. The evidence agent drafts justifications
and **has no code path that sets a status**; where evidence merely *mentions* a
CVE rather than supporting a determination it proposes `under_investigation`,
never `not_affected`. CSAF 2.0 export validates.

**S13 is the review gate and self-conformance.** An assessor cannot approve their
own assessment *however senior* — a partner who wrote it is still the same pair
of eyes. Unapproved exports carry "AI-assisted draft — not reviewed". Log
redaction keeps paths, hostnames and BOM payloads out of storage. Resubmission
diffing is **per field**: two compensating changes give an identical total from
different verdicts, and a total-only diff would report "no change" for exactly the
resubmission worth looking at.

Our own AIBOM declares both governance statements, including plainly that this
product **does not issue legal or regulatory opinions**.

## Run the demo

```bash
make demo      # SQLite, no Docker, no Postgres, no Redis
```

Sign in as `assessor@firm-a.example` / `demo-password-1234`, run the assessment
and drill from the five-lane strip into 4.2(5) and its clause reference. The
seeded submission carries **real cdxgen output** — 76 components — so the score
is a real score.

**Not yet built** (and not claimed): CBOM/QBOM (S14) and HBOM (S16) still report
`lane_absent`; no DOCX/PDF/XLSX export yet (S15), so the deliverable is JSON. BOM payloads are held in a
`bom_documents.payload` column until object storage lands in S13; that column is
the wrong blast radius for an architecture disclosure and is marked interim in
the model. Google OAuth has a controller path but no live token exchange.

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
