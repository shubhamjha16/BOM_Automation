# BOM Automation — Architecture

**One repository, two applications, five assessment lanes, one tenant boundary.**

Conformance basis: *CERT-In Technical Guidelines on SBOM, QBOM & CBOM, AIBOM and HBOM*,
**v2.0, 09.07.2025**.

Companion documents: [PRODUCT_SPECIFICATION.md](PRODUCT_SPECIFICATION.md) ·
[DATA_MODEL.md](DATA_MODEL.md) · [COMPLIANCE_MATRIX.md](COMPLIANCE_MATRIX.md)

---

## 1. System context

```mermaid
graph LR
    subgraph people["People"]
        PARTNER["Partner<br/>sees every supplier's score"]
        ASSESSOR["Assessor<br/>runs assessments, cannot approve"]
        MANAGER["Manager<br/>approves, never their own"]
        CLIENTUSER["Client<br/>read-only, one engagement"]
    end

    subgraph product["BOM Automation"]
        CONSOLE["Console<br/>Vite + React 19"]
        API["API<br/>FastAPI, async"]
        WORKER["Worker<br/>arq"]
    end

    subgraph suppliers["Suppliers"]
        UPLOAD["BOM upload<br/>CycloneDX / SPDX"]
        REPO["Connected repository<br/>GitHub / GitLab"]
        REGISTER["Asset register<br/>CSV / XLSX"]
    end

    subgraph feeds["External feeds — read only, staleness reported"]
        NVD["NVD<br/>CVE + CVSS"]
        KEV["CISA KEV"]
        EOL["endoflife.date"]
        OSV["OSV / GHSA"]
    end

    subgraph out["Outbound"]
        PR["Pull-request check<br/>conformance status"]
        WEBHOOK["Signed webhook<br/>HMAC-SHA256"]
        CSAF["CSAF 2.0 advisory"]
    end

    PARTNER --> CONSOLE
    ASSESSOR --> CONSOLE
    MANAGER --> CONSOLE
    CLIENTUSER --> CONSOLE
    CONSOLE --> API
    UPLOAD --> API
    REGISTER --> API
    REPO --> WORKER
    API --> WORKER
    WORKER --> NVD
    WORKER --> KEV
    WORKER --> EOL
    WORKER --> OSV
    WORKER --> PR
    WORKER --> WEBHOOK
    API --> CSAF

    style product fill:#e8f5e9,stroke:#2e7d32
    style feeds fill:#e3f2fd,stroke:#1565c0
```

The product is built **consumer-side**: a client *receiving* BOMs wants conformance
scoring, supplier chasing and gap reports. A vendor *shipping* to government wants
generation, identifier mapping and VEX maintenance. Same guideline, opposite products.
This one assesses, and generation exists only because assessing a supplier's SBOM against
one we generated from their repository is the strongest finding the tool can produce.

---

## 2. Containers

```mermaid
graph TB
    subgraph edge["Edge"]
        VERCEL["Vercel<br/>console, static"]
        RENDER["Render<br/>api + worker"]
    end

    subgraph api["API process — FastAPI"]
        MW["BodySizeLimitMiddleware<br/>refuses before reading"]
        CORS["CORS"]
        ROUTERS["routers/<br/>handlers under 15 lines, zero SQL"]
        CONTROLLERS["controllers/<br/>orchestration"]
        DEPS["routers/deps.py<br/>the only place org scope is resolved"]
        HANDLERS["exception handlers<br/>401 · 403 · 404 · 422 · 429 · 501"]
    end

    subgraph services["services/ — the product"]
        CAT["catalogue/<br/>82 minimum elements, 5 tables"]
        SCORE["score/<br/>coverage · weighting · verdict"]
        GRAPH["graph/<br/>LangGraph, no module over 200 lines"]
        INGEST["ingest/<br/>CycloneDX · SPDX · asset register"]
        CORR["correlate/<br/>cross-BOM rules"]
        KB["kb/<br/>feed sync, TTL cached"]
        AGENTS["agents/<br/>bounded loop, proposals only"]
        RENDERSVC["render/<br/>PDF · DOCX · XLSX · JSON"]
        ACCESS["access/<br/>matrix · authz · audit"]
        QUOTA["quota/<br/>plans · limits · rate"]
        OBS["observability/<br/>log reconstruction"]
        SELF["self/<br/>our own conformance"]
    end

    subgraph repos["repositories/ — TENANCY LIVES HERE"]
        BASE["TenantScopedRepository<br/>scoped() is the only query entry"]
    end

    subgraph data["Data"]
        PG[("PostgreSQL<br/>ap-south-1")]
        REDIS[("Redis<br/>arq queue")]
        S3[("Object storage<br/>SSE-KMS, per-client key")]
    end

    subgraph worker["Worker process — arq"]
        TASKS["workers/tasks.py"]
        SYNC["sync_kb<br/>feeds on a schedule"]
        SANDBOX["repo/sandbox.py<br/>--network none"]
    end

    VERCEL --> ROUTERS
    RENDER --> ROUTERS
    MW --> CORS --> ROUTERS
    ROUTERS --> DEPS
    ROUTERS --> CONTROLLERS
    CONTROLLERS --> services
    services --> repos
    repos --> PG
    ROUTERS --> HANDLERS
    CONTROLLERS --> REDIS
    REDIS --> TASKS
    TASKS --> GRAPH
    TASKS --> SANDBOX
    SYNC --> KB
    KB --> PG
    RENDERSVC --> S3

    style repos fill:#ffebee,stroke:#c62828,stroke-width:3px
    style services fill:#e8f5e9,stroke:#2e7d32
```

**Why tenancy is red.** A BOM is an architecture disclosure and this system holds many
suppliers' at once, so cross-tenant reachability is the failure that ends the product.
Routers are the wrong place to enforce it: a new endpoint is one forgotten `WHERE` clause
away from leaking, and the omission looks like nothing at review. So every repository is
constructed *with* an org scope, `scoped()` is the only method that builds a query, and a
test parses the repository package's AST to fail the build if any method constructs a bare
`select(self.model)`.

---

## 3. The assessment graph

```mermaid
graph LR
    START(( )) --> INTAKE[intake<br/>conserve the entry count]
    INTAKE --> DETECT[detect<br/>format per document]
    DETECT --> FANOUT{fanout}

    FANOUT --> SBOM[sbomLane<br/>s.4.2 · 21 elements]
    FANOUT --> CBOM[cbomLane<br/>s.8.4 · 20 elements]
    FANOUT --> QBOM[qbomLane<br/>s.8.5 · 10 elements]
    FANOUT --> AIBOM[aibomLane<br/>s.9.3 · 16 elements]
    FANOUT --> HBOM[hbomLane<br/>s.10.2 · 15 elements]

    SBOM --> JOIN[join]
    CBOM --> JOIN
    QBOM --> JOIN
    AIBOM --> JOIN
    HBOM --> JOIN

    JOIN --> ENRICH[enrich<br/>NVD · KEV · EOL]
    ENRICH --> CORRELATE[correlate<br/>cross-BOM rules]
    CORRELATE --> GATE[conformanceGate<br/>every citation resolves]
    GATE --> END(( ))

    style GATE fill:#ffebee,stroke:#c62828,stroke-width:2px
    style FANOUT fill:#e3f2fd,stroke:#1565c0
```

**All five lane nodes are edged in unconditionally.** A lane the engagement did not enable
reports `lane_not_applicable` from *inside* the node. Skipping the edge instead would make
"not applicable" indistinguishable from "nobody ran it" — and those are the two answers a
client most needs told apart.

**`enrich` sits between `join` and `correlate`, not after it.** The feeds populate the KEV
data that the `vexCoverage` rule reads; correlating first would evaluate that rule against
entities whose vulnerabilities had not been looked up yet, and report a clean result.

**Layout constraint.** No module in `services/graph/` exceeds 200 lines and `builder.py`
contains zero prompt text. Prompts are data, one module per node, under `graph/prompts/`.

### What each lane node actually does

```mermaid
flowchart TD
    A[lane node invoked] --> B{"lane in<br/>engagement's<br/>enabled_lanes?"}
    B -- no --> NA["verdict = lane_not_applicable<br/>excluded from overall score"]
    B -- yes --> C{lane implemented?}
    C -- no --> ABS1["verdict = lane_absent<br/>documents stored, not scored<br/>+ an error, so nothing vanishes"]
    C -- yes --> D{"any document<br/>for this lane?"}
    D -- no --> ABS2["verdict = lane_absent<br/>a reported finding"]
    D -- yes --> E["run body in a thread<br/>bounded by LANE_TIMEOUT_SECONDS"]
    E --> F{outcome}
    F -- timeout --> TO["verdict = lane_timeout<br/>a finding, not a crash"]
    F -- raised --> ERR["verdict = fail<br/>exception recorded<br/>other four lanes unaffected"]
    F -- ok --> G["parse → score → verdict"]
    G --> H["write node_run<br/>+ lane_started / lane_complete"]
    NA --> H
    ABS1 --> H
    ABS2 --> H
    TO --> H
    ERR --> H

    style TO fill:#fff8e1,stroke:#f9a825
    style ERR fill:#fff8e1,stroke:#f9a825
```

**Lanes fail independently.** An absent or timed-out lane is a *reported finding*, never a
crashed assessment. A client who submitted five documents and gets an HTTP 500 learns
nothing; a client who gets four lane verdicts and "CBOM exceeded its 120-second budget"
knows exactly where they stand.

**On what the fan-out actually buys.** The lanes run through `asyncio.to_thread` and their
intervals genuinely overlap, which is what the isolation above depends on. It is **not** a
speedup: scoring is pure Python and holds the GIL, so five lanes over one document cost
about what five sequential lanes cost, plus scheduling. Measured figures are in
`dist/scale-report.md`; the measurement that established it is recorded in
`services/graph/laneRunner.py`.

---

## 4. Scoring pipeline

```mermaid
flowchart LR
    subgraph parse["ingest/"]
        P1["detect format"] --> P2["parse"] --> P3["normalise<br/>canonical + source-shaped keys"]
        P3 --> P4["entities"]
        P3 --> P5["rejected → raw_entries"]
        P3 --> P6["document metadata<br/>author · timestamp"]
    end

    subgraph elements["catalogue/"]
        E1["82 minimum elements"]
        E2["tier: critical 3.0<br/>standard 2.0<br/>contextual 1.0"]
        E3["determinability:<br/>auto · enrich · human"]
        E4["scope: entity · document"]
    end

    subgraph measure["score/coverage.py"]
        C1["applicable entities<br/>out-of-scope assets leave<br/>the DENOMINATOR"]
        C2["populated = probe passes"]
        C3["coverage = populated / total"]
    end

    subgraph verdicts["score/fieldCheck.py"]
        V1{determinability}
        V1 -- human --> VH["not_determinable<br/>+ consumer_action<br/>excluded from score"]
        V1 -- auto or enrich --> VC{coverage}
        VC -- "= 1.0" --> VP["present"]
        VC -- "0 < c < 1" --> VPART["partial → absent<br/>partial coverage is not a pass"]
        VC -- "= 0" --> VA["absent"]
    end

    subgraph roll["score/weighting.py + verdict.py"]
        W1["weighted mean over<br/>supplier-scored elements"]
        W2{"critical element<br/>at zero coverage?"}
        W2 -- yes --> WF["FAIL at any score"]
        W2 -- no --> W3{score}
        W3 -- ">= 85" --> WP["pass"]
        W3 -- "60 to 85" --> WC["conditional — remediable"]
        W3 -- "< 60" --> WFAIL["fail"]
        WP --> W4{"high-severity<br/>configuration finding?"}
        W4 -- yes --> WCAP["capped at conditional"]
    end

    P4 --> C1
    P6 --> C1
    E1 --> C1
    E4 --> C1
    C1 --> C2 --> C3 --> V1
    E3 --> V1
    VP --> W1
    VPART --> W1
    VA --> W1
    E2 --> W1
    W1 --> W2

    style VH fill:#fff8e1,stroke:#f9a825
    style WF fill:#ffebee,stroke:#c62828
    style WCAP fill:#fff8e1,stroke:#f9a825
```

Four rules in that diagram are the product rather than preferences:

1. **Partial coverage is not a pass.** Licences on 12 of 400 components has not met
   s.4.2(5). The field verdict is `absent` and the coverage ratio is reported beside it.
2. **Out-of-scope assets leave the denominator.** A classical security level is meaningful
   for an algorithm and meaningless for a certificate. Counting certificates as *absent* on
   algorithm fields would make the score measure document composition rather than
   declaration quality; counting them as *populated* would inflate it. They are excluded.
3. **A critical gap fails at any score.** A BOM with no versions can score respectably on
   descriptive fields while being useless for every purpose the guideline exists to serve.
4. **A configuration finding caps the verdict.** Coverage measures whether a supplier
   *declared* their cryptography; it cannot see that what they declared is an expired
   certificate, TLS 1.0 and 3DES. A lane reporting `pass` on that document would be
   complete, arithmetically correct, and wrong in the client's favour.

---

## 5. Cross-BOM correlation

The class of finding no single-lane tool can produce.

```mermaid
graph TB
    subgraph inputs["Lane outputs available"]
        S[sbom]
        C[cbom]
        Q[qbom]
        A[aibom]
        H[hbom]
    end

    subgraph rules["correlate/rules.py"]
        R1["cryptoInSbom · s.8.4.1.2 · high<br/>OpenSSL in the SBOM, no CBOM"]
        R2["modelDepsInSbom · s.9.3(6) · high<br/>AIBOM names torch, SBOM does not"]
        R3["algorithmQuantumExposure · s.8.5.1 · high<br/>RSA declared, no PQC migration path"]
        R4["firmwareInHbom · s.10.2.4 · medium<br/>declared firmware with no SBOM coverage"]
        R5["vexCoverage · rec. 7.1.6 · critical<br/>pending: needs the VEX store populated"]
    end

    subgraph out["Report"]
        F["findings<br/>each with left_ref and right_ref"]
        SK["skipped<br/>with the lane that was missing"]
    end

    S --> R1
    S --> R2
    A --> R2
    C --> R3
    Q --> R3
    H --> R4
    S --> R4
    R1 --> F
    R2 --> F
    R3 --> F
    R4 --> F
    R5 --> SK

    style R5 fill:#f5f5f5,stroke:#9e9e9e,stroke-dasharray: 4 4
```

**A rule whose lanes are absent is `skipped`, never silently passed.** "Did not run" and
"found nothing" are different answers, and a single-lane submission produces **zero**
correlation findings — a client with only an SBOM has not failed to declare their
cryptography, they were never asked to. Correlating against nothing is invention.

Correlation findings cite the guideline exactly as field verdicts do, so they pass the same
conformance gate. Otherwise the one class of finding no other tool can produce would be the
one class nobody verified.

---

## 5a. Retrieval-augmented drafting

The one place a language model enters this system, and the boundary that keeps §11
true across it.

```mermaid
flowchart TB
    subgraph ingest["Ingest — masking happens HERE, before any write"]
        I1[house prose] --> I2["mask_facts()<br/>percentages · clauses · CVEs<br/>· dates · versions → placeholders"]
        I2 --> I3["assert_masked()<br/>verified, not trusted"]
        I3 --> I4[chunk on paragraphs]
        I4 --> I5[embed] --> I6[(corpus_chunks<br/>org_id + vector 384)]
    end

    subgraph search["Retrieve — org-scoped, always"]
        Q[query] --> V["vector<br/>cosine"]
        Q --> L["lexical<br/>term overlap"]
        I6 --> V
        I6 --> L
        V --> F["reciprocal rank fusion<br/>position, not score"]
        L --> F
    end

    subgraph gen["Augment and generate"]
        F --> A["prompt: FACTS + HOUSE WORDING<br/>facts from the scoring engine,<br/>wording from the corpus"]
        A --> G[generator]
        G --> VER{"verify()<br/>every figure and clause<br/>traces to FACTS?"}
        VER -- no --> REF["REFUSED<br/>blocked_conformance"]
        VER -- yes --> OUT[section]
    end

    style I2 fill:#fff8e1,stroke:#f9a825
    style VER fill:#ffebee,stroke:#c62828,stroke-width:2px
    style REF fill:#ffebee,stroke:#c62828
```

**Facts are masked on the way *in*, not on the way out.** A figure that never
entered the corpus cannot be retrieved by a future code path that forgets to mask,
cannot be reached by a manipulated query, and cannot survive a database dump into
somewhere less careful. What is stored is the sentence shape — which is the entire
reason to retrieve house wording:

```
"Licences were absent across 388 of 412 components, failing 4.2(5)."
→ "Licences were absent across ⟨count⟩ of ⟨count⟩ components, failing ⟨clause⟩."
```

**Fusion reads position, not score.** Cosine similarity sits around 0.2–0.4 for
related prose; term overlap is a fraction that frequently saturates at exactly 1.0.
Adding or averaging those two scales does not combine two opinions — it lets
lexical dominate whenever it saturates. RRF gives each retriever an equal vote.

**`verify()` is the boundary, and it checks provenance rather than resolution.**
The conformance gate downstream confirms that a clause reference *resolves*; a
fabricated `4.2(4)` resolves perfectly, because it is a real clause. So every
figure and clause in a generated draft is checked against the facts that were
supplied, and an unsupported one is a refusal — the job goes to
`blocked_conformance` and is **not retried**, because re-running the same prompt
against the same model produces the same class of fabrication and eventually ships
one.

**Tenancy is the property this component lives or dies on.** Every other table
answers questions about one client; this one exists to surface passages written for
*other* engagements, and only the org scope separates "another engagement of ours"
from "a competitor's". `tests/test_retrieval.py` seeds the other tenant with the
**best possible match** for the query, so a missing predicate surfaces as the first
result rather than hiding in a tail.

---

## 6. Request lifecycle and where each rule is enforced

```mermaid
sequenceDiagram
    autonumber
    participant C as Console
    participant M as BodySizeLimit
    participant D as deps.py
    participant Q as QuotaService
    participant R as Router
    participant CT as Controller
    participant RP as Repository
    participant PG as Postgres
    participant RD as Redis
    participant W as Worker

    C->>M: POST /api/v1/submissions
    M->>M: over MAX_BOM_MB? refuse before reading
    M->>D: verified JWT
    D->>D: expect="access" — a refresh or mfa_pending token is not enough
    D->>D: MFA satisfied?
    D->>D: resolve org_id + actor_id from claims
    D->>R: repositories constructed WITH the org scope
    R->>Q: check_submission + check_components
    Q--xC: 429 with quota, limit, usage, reset, remedy
    R->>CT: create_submission
    CT->>RP: add(submission)
    RP->>RP: refuse a write whose org_id differs from the scope
    RP->>PG: INSERT
    CT->>RP: add_document per lane
    R-->>C: 201 with the submission id

    C->>R: POST /submissions/{id}/commit
    R->>CT: commit_submission (idempotency key)
    CT->>RD: enqueue assess_submission
    CT-->>C: job_id
    W->>RD: dequeue
    W->>W: run the graph — five lanes concurrently
    W->>PG: lane_results, field_verdicts, node_runs
    C->>R: GET /jobs/{id}/events
    R-->>C: SSE, per-lane progress — five tracks, not one spinner
```

---

## 7. Tenancy: the four denied paths

```mermaid
flowchart TD
    START["Firm A requests<br/>Firm B's submission"] --> SC["repository.scoped()<br/>adds WHERE org_id = A"]
    SC --> Q["query returns nothing"]
    Q --> PROBE["_audit_if_another_tenants<br/>one unscoped SELECT of org_id only"]
    PROBE --> OWN{"owned by<br/>another org?"}
    OWN -- no --> ORD["ordinary 404<br/>not audited — noise buries signal"]
    OWN -- yes --> AUD["record_out_of_band<br/>access.cross_tenant.denied"]
    AUD --> SESS["its OWN session, committed independently"]
    SESS --> WHY["the denial ends in an exception;<br/>a row on the request session<br/>would roll back with the 404"]
    WHY --> RESP["404 — same body, same status<br/>as a genuine miss"]
    ORD --> RESP

    style AUD fill:#fff8e1,stroke:#f9a825
    style RESP fill:#e8f5e9,stroke:#2e7d32
```

All four access paths are denied and tested: **read, list, search-by-checksum, and
download**. All four return **404, not 403** — a 403 would confirm the resource exists, and
so would the word "forbidden" anywhere in the body.

403 is correct in exactly one place: a caller inside their own org whose *role* does not
permit the action. There, acknowledging the resource leaks nothing.

### The authorization matrix

```mermaid
graph LR
    subgraph roles["5 roles"]
        P[partner]
        M[manager]
        A[assessor]
        RO[readonly]
        CL[client]
    end
    subgraph res["11 resources"]
        R1[submission]
        R2[assessment]
        R3[lane_result]
        R4[vex_statement]
        R5[identifier_mapping]
        R6[supplier_registry]
        R7[engagement]
        R8[user]
        R9[audit_event]
        R10[maturity]
        R11[repository]
    end
    subgraph acts["7 actions"]
        A1[read]
        A2[list]
        A3[create]
        A4[update]
        A5[delete]
        A6[approve]
        A7[export]
    end
    roles --> res --> acts
```

**55 cells, every one decided.** `missing_cells()` must return empty, so adding a resource
forces a decision about who may reach it rather than inheriting whatever the first endpoint
allowed. The matrix is closed — an unlisted pairing is denied, never permitted by default.

Four invariants are asserted over the whole table:

- Only `partner` may **delete** anything. Deletion is the one action with no undo.
- No role may **write** the audit trail. An audit trail the application can edit is not one.
- **read implies list.** Denied listing plus permitted reads is an enumeration oracle: a
  caller learns what exists from the difference between the two answers.
- No role may **update what it cannot read**.

The role predicates in `authz.py` read this table rather than restating it, and an AST test
fails the build if one grows a second copy of a role list.

---

## 8. Repository ingestion and generation

```mermaid
sequenceDiagram
    autonumber
    participant U as Assessor
    participant API as API
    participant W as Worker
    participant SB as Sandbox
    participant CDX as cdxgen

    U->>API: connect repository (least-privilege scopes)
    API->>API: assert_scopes_minimal — refuse a broader grant than needed
    U->>API: generate
    API->>W: enqueue generate_from_repo
    W->>SB: choose a sandbox
    alt container runtime available
        SB->>CDX: run with --network none
        CDX-->>SB: CycloneDX 1.6
    else no container runtime
        SB--xW: SandboxUnavailable — REFUSE
        Note over SB,W: Generation resolves dependencies, which<br/>executes code from the repository under<br/>assessment. Untrusted code is never run<br/>unprotected.
    end
    W->>W: diff generated against declared
    W-->>U: "54 components present in the build,<br/>absent from the declaration"
```

**`LocalSandbox` refuses untrusted work rather than degrading.** Dependency resolution runs
the repository's own build scripts. Without network isolation, a hostile `package.json`
`postinstall` reaches our infrastructure. A fallback that "just runs it locally" is exactly
how that becomes a breach, so the honest failure mode is a refusal that names the reason.

---

## 9. The CI conformance gate

```mermaid
sequenceDiagram
    autonumber
    participant DEV as Developer
    participant GH as GitHub
    participant CI as ci/checkRun.py + policy.py
    participant ENG as Scoring engine
    participant PR as Pull request

    DEV->>GH: open a PR adding a dependency
    GH->>CI: pull_request event
    CI->>ENG: generate + assess
    ENG-->>CI: score, failing clauses, offending components
    CI->>CI: policy.py — per-engagement threshold
    alt mode = block
        CI->>PR: failing check — "4.2(5) Licence: left-pad@1.3.0"
    else mode = warn (the default)
        CI->>PR: neutral check, same finding
        Note over CI,PR: A gate that blocks on day one gets<br/>disabled by the platform team on day two.
    end
```

**This repository is the first one connected.** The gate runs against our own pull requests
before any client sees it, and our own conformance score is published whatever it says.

---

## 10. Observability

```mermaid
flowchart LR
    subgraph bind["assessment_context — bound once"]
        B1[submission_id]
        B2[job_id]
        B3[org_id]
    end

    subgraph emit["Every lane, whatever it did"]
        E1[lane_started]
        E2["lane_complete<br/>verdict · entity_count · latency_ms"]
        E3["lane_failed<br/>then still completes"]
    end

    subgraph proc["structlog processors"]
        P1[merge_contextvars]
        P2[add_log_level]
        P3[TimeStamper]
        P4["redaction_processor<br/>LAST before rendering"]
        P5[JSONRenderer]
    end

    subgraph rebuild["observability/trace.py"]
        R1["reconstruct(lines, submission_id)"]
        R2["5 LaneLifecycle objects"]
        R3["missing · incomplete · whole"]
        R4["latency_percentiles — per lane"]
    end

    bind --> emit --> proc --> R1 --> R2 --> R3
    R2 --> R4

    style P4 fill:#ffebee,stroke:#c62828
```

**One `submission_id` reconstructs all five lane lifecycles.** Read literally, that is the
hard version: the lane that was disabled or received no document does no work, has nothing
interesting to say, and is therefore exactly the lane that gets left out of the logs — and
exactly the lane a client asks about. So `lane_started` is emitted before any branch.

Correlation comes from `structlog.contextvars`, bound once per assessment and inherited by
the lane threads because `asyncio.to_thread` copies the context. Threading the identifiers
through call signatures would work until the first place somebody forgot, and that place is
the one somebody would eventually ask about.

`started-but-never-ended` stays distinguishable from `never-reached`. A hung lane and an
unreached lane are different incidents.

**Redaction runs last**, so nothing a later processor adds escapes it. Logs outlive
engagements.

---

## 11. Quotas

```mermaid
flowchart TD
    REQ[request] --> RL{"rate limit<br/>per org, sliding window"}
    RL -- over --> R429A["QuotaExceeded"]
    RL -- ok --> SUB{"submissions this month<br/>vs plan limit"}
    SUB -- over --> R429B["QuotaExceeded<br/>resets next month"]
    SUB -- ok --> COMP{"declared entries<br/>vs components limit"}
    COMP -- over --> R429C["QuotaExceeded<br/>REFUSED, not truncated<br/>no Retry-After: nothing resets"]
    COMP -- ok --> WORK[do the work]

    R429A --> H["app-level exception handler"]
    R429B --> H
    R429C --> H
    H --> BODY["429 + Retry-After<br/>quota · limit · used · plan<br/>resets_at · remedy"]
    BODY --> UI["QuotaExceededState<br/>role=status, NOT alert"]

    style R429C fill:#ffebee,stroke:#c62828
    style H fill:#e8f5e9,stroke:#2e7d32
```

**The handler is registered on the app, not per route.** That is what makes "never a 500"
hold: a `QuotaExceeded` raised from a service the route never expected would otherwise
surface as a 500 — precisely the failure the requirement names.

**Component overage is refused, not truncated.** Scoring the first 5,000 components of a
40,000-component estate would produce a figure that looks complete and describes an eighth
of the software — the partial-coverage failure, arriving through the billing system.

**The UI renders it as a status, not an alert.** The request was valid and the service is
healthy. Styling a billing limit as an outage teaches clients to read it as one.

---

## 12. Frontend structure

```mermaid
graph TB
    subgraph global["src/global/"]
        AC["apiClient.ts<br/>the single HTTP entry point"]
        AT["apiTypes.ts<br/>re-export of generated OpenAPI types"]
        ER["errors.ts<br/>ApiError: isNotFound, isQuotaExceeded"]
    end

    subgraph features["src/features/ — self-contained"]
        F1["auth/"]
        F2["submissions/"]
        F3["assessments/"]
        F4["lanes/"]
        F5["elements/"]
        F6["identifiers/"]
        F7["vex/"]
        F8["maturity/"]
        F9["dashboard/"]
        F10["quota/"]
    end

    subgraph shared["src/components + shared/"]
        C1["conformance/<br/>VerdictBadge · LaneStrip<br/>ScoreDial · ClauseRef"]
        C2["shared/constants/<br/>verdicts · tiers · lanes · roles"]
    end

    subgraph pages["src/pages/"]
        PG1[SignInPage]
        PG2[SubmissionsPage]
        PG3[SubmissionDetailPage]
        PG4[AssessmentPage]
        PG5[CataloguePage]
        PG6[MaturityPage]
    end

    features --> AC
    AC --> AT
    AC --> ER
    pages --> features
    pages --> shared
```

Each feature is self-contained: `components/ hooks/ services/ store.ts types.ts index.ts`.
Server state is TanStack Query; client state is Zustand — server state is not client state.

**API types are generated, never hand-written.** `packages/api-types/` is produced from the
backend's OpenAPI schema and CI fails if it is stale, so a backend shape change cannot
reach the console as a runtime surprise.

Three presentation rules the console enforces:

- **Null is an em dash, never `0%`.** An unscored submission and a zero-scoring one look
  completely different to a reader, and only one of them is a catastrophe.
- **A 404 means "not found", never "no access."** Tenancy returns 404 so existence does not
  leak; a console that renders "you lack permission" leaks exactly what the 404 protects.
- **Attested must never look like evidenced.** The maturity view styles an attested verdict
  with a dashed border and italics, because a scorecard where a client's word and a checked
  artifact render identically is a scorecard that invites a client to trust the wrong half.

---

## 13. Deployment

```mermaid
graph LR
    subgraph gh["GitHub Actions — path filtered"]
        BE["backend.yml<br/>uv sync · ruff · mypy · pytest<br/>uv export drift · pip-audit<br/>scale budget · catalogue audit"]
        FE["frontend.yml<br/>yarn lint · tsc -b · vitest · build"]
        CONF["conformance.yml<br/>our own PR check"]
        SB["self-bom.yml<br/>SBOM per release, s.2.3"]
    end

    subgraph deploy["Deployment"]
        R1["Render: api<br/>alembic upgrade head as PRE-DEPLOY"]
        R2["Render: worker"]
        R3[("Render: Postgres")]
        R4[("Render: Redis")]
        V["Vercel: console"]
    end

    BE --> R1
    BE --> R2
    FE --> V
    R1 --> R3
    R2 --> R3
    R2 --> R4

    style CONF fill:#e8f5e9,stroke:#2e7d32
```

**`alembic upgrade head` is a pre-deploy step, not an app-startup hook.** A migration that
runs at startup runs once per instance, concurrently, on a rolling deploy.

**Path filtering is a stated requirement, not an optimisation.** A pull request touching
only `frontend/` must not run the backend suite — a CI that always runs everything is a CI
people learn to ignore.

**`pip-audit --strict` is blocking.** A supply-chain conformance tool shipping
known-vulnerable dependencies is not commercially survivable.

**`scale` is blocking too.** The failure it catches is algorithmic: a per-component cost
that quietly became quadratic passes every functional test and turns a client's
50,000-component estate into a timeout.

---

## 14. Measured performance

From `dist/scale-report.md`, regenerated by `make scale`:

| Measurement | Figure |
|---|---|
| 50,000-component SBOM, wall clock | **~5 s** (~4 s CPU) |
| Peak RSS for that document | **~210 MB** |
| Per component | ~0.1 ms |
| Stated budget | 30 s / 1024 MB — loose on purpose |
| 20 concurrent five-lane assessments | ~4 s total |
| Throughput | ~12,000 components/second |
| Lane intervals overlap | yes |
| Every submission reconstructable from logs | yes |

The budget is four times the measurement deliberately. A budget set *at* the measurement
fails on a slow CI runner, gets called flaky, and gets deleted. What the tests actually
guard is **linearity** — a wall-clock budget catches a slow machine, not an accidental
O(n²).

Concurrency **shares** throughput rather than adding to it. What it buys is that no client
waits behind another client's whole queue, not that the machine does more work. Repository
generation is reported separately because it takes minutes rather than seconds.

---

*See [PRODUCT_SPECIFICATION.md](PRODUCT_SPECIFICATION.md) for the functional specification,
[DATA_MODEL.md](DATA_MODEL.md) for the schema, and
[COMPLIANCE_MATRIX.md](COMPLIANCE_MATRIX.md) for the clause-by-clause mapping.*
