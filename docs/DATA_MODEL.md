# BOM Automation — Data Model

**30 tables, 9 migrations, one tenant boundary.** Every diagram here is generated from
the SQLAlchemy models in `backend/app/models/` and matches `alembic/versions/`.

Conformance basis: *CERT-In Technical Guidelines on SBOM, QBOM & CBOM, AIBOM and HBOM*,
**v2.0, 09.07.2025**. Every clause reference stored in this schema resolves to a row in
`minimum_elements` for the pinned `guideline_versions.version`, or the assessment refuses
to render.

---

## 1. Design rules the schema enforces

| Rule | How the schema carries it |
|---|---|
| **Tenancy is enforced at the repository layer, never the router** | Every tenant-scoped table carries `org_id` with an FK to `orgs`. No repository method accepts an id alone; `TenantScopedRepository.scoped()` is the only query entry point. |
| **A score is never defaulted to zero** | `submissions.overall_score` and `lane_results.score` are `NUMERIC(5,2) NULL`. Null means *not scored*; zero is a real and much worse verdict. |
| **`not_determinable` is never `compliant`** | `field_verdicts.verdict` is a three-state enum. `not_determinable` rows carry a mandatory `consumer_action` and are excluded from the weighted score. |
| **`lane_not_applicable` ≠ `lane_absent`** | Distinct values of the `lane_verdict` enum. The first is excluded from the overall score; the second is a reported finding. |
| **Nothing is dropped silently** | `bom_documents.entry_count = parsed_count + rejected_count`, and every rejection is a `raw_entries` row with a reason. |
| **A clause reference must resolve** | `field_verdicts.clause` is checked against `minimum_elements` for the pinned guideline version before any export renders. |
| **Agents research; they never decide** | `registry_proposals` is a separate table from `supplier_registry_entries`. A proposal reaches the registry only through a human review that writes `verified_by`. |
| **Attested is never evidenced** | Maturity verdicts carry a `basis`; an evidenced verdict without an artifact reference cannot be constructed. |
| **A terminal job stays terminal** | `jobs.terminal_at` plus a conditional `UPDATE ... WHERE terminal_at IS NULL`, so a late worker cannot resurrect a finished job. |

---

## 2. Tenancy and identity

```mermaid
erDiagram
    ORGS ||--o{ USERS : "employs"
    ORGS ||--o{ CLIENTS : "advises"
    ORGS ||--o{ ENGAGEMENTS : "scopes"
    CLIENTS ||--o{ ENGAGEMENTS : "is assessed under"
    ORGS ||--o{ AUDIT_EVENTS : "records"
    USERS ||--o{ AUDIT_EVENTS : "acted"

    ORGS {
        uuid id PK
        string name
        string plan "starter|practice|firm|enterprise"
        int seats
        timestamptz created_at
    }

    USERS {
        uuid id PK
        uuid org_id FK
        string email "unique per org"
        string hashed_password "null for OAuth-only"
        string google_sub "unique, nullable"
        enum role "partner|manager|assessor|readonly|client"
        bool mfa_enabled
        string mfa_secret "TOTP, never logged"
        bool is_active "deactivation takes effect immediately"
        timestamptz created_at
    }

    CLIENTS {
        uuid id PK
        uuid org_id FK
        string name
        enum sector "govt|psu|essential|private"
        timestamptz created_at
    }

    ENGAGEMENTS {
        uuid id PK
        uuid org_id FK
        uuid client_id FK
        string title
        enum kind "procurement_review|supplier_onboarding|estate_assessment"
        array enabled_lanes "drives lane_not_applicable"
        enum status "active|paused|closed"
        timestamptz created_at
    }

    AUDIT_EVENTS {
        uuid id PK
        uuid org_id FK
        uuid actor_id FK "null for system actions"
        string action "auth.*, access.cross_tenant.denied, submission.created"
        string resource
        string resource_id
        jsonb meta "identifiers and outcomes only, never BOM content"
        string ip
        timestamptz created_at
    }
```

**`enabled_lanes` is the applicability switch.** A client with no quantum hardware has
nothing to declare, so QBOM reports `lane_not_applicable` and leaves the overall score
alone. A client running cryptography with no CBOM has *failed to declare it*, and that is
`lane_absent` — a finding. Conflating the two produces either a false accusation or a
false pass, which is why it is data rather than an inference.

**`audit_events` is the only record of a refused cross-tenant read.** The caller receives
a 404 indistinguishable from a genuine miss, so nothing else records that the attempt
happened. The row deliberately does **not** name the owning org: knowing the resource
belonged to *someone else* is what a reviewer needs, and naming the victim would place
one tenant's identity inside another tenant's audit trail.

---

## 3. Submission and ingestion

```mermaid
erDiagram
    ENGAGEMENTS ||--o{ SUBMISSIONS : "receives"
    USERS ||--o{ SUBMISSIONS : "submitted"
    SUBMISSIONS ||--o{ BOM_DOCUMENTS : "carries 1..5"
    BOM_DOCUMENTS ||--o{ RAW_ENTRIES : "rejected entries"

    SUBMISSIONS {
        uuid id PK
        uuid org_id FK
        uuid engagement_id FK
        uuid submitted_by FK
        timestamptz received_on
        enum status "received|parsed|scored|assessed|returned|accepted"
        numeric overall_score "NULL until scored, never 0"
        string overall_verdict
        timestamptz terminal_at
        timestamptz created_at
    }

    BOM_DOCUMENTS {
        uuid id PK
        uuid org_id FK
        uuid submission_id FK
        string lane "sbom|cbom|qbom|aibom|hbom, declared not sniffed"
        enum format "CycloneDX|SPDX"
        string spec_version
        string checksum "SHA-256, deduplicated per org not globally"
        string filename
        int size_bytes
        string s3_key "SSE-KMS, per-client key"
        jsonb payload "interim store; moves to object storage"
        int entry_count "parsed + rejected must equal this"
        int parsed_count
        int rejected_count
        string doc_author "document-scoped 4.2(19)"
        timestamptz doc_timestamp "document-scoped 4.2(20)"
        enum status "received|parsed|unreadable"
        timestamptz created_at
    }

    RAW_ENTRIES {
        uuid id PK
        uuid org_id FK
        uuid bom_document_id FK
        int ord "position in the source document"
        string parse_status "rejected"
        text reason "actionable, names the field"
        string ref "bom-ref or SPDXID where present"
        jsonb payload "the entry as received"
        timestamptz created_at
    }
```

**The conservation invariant.** `entry_count = parsed_count + rejected_count` for every
document, and each rejection is a durable row. This answers the question that decides
whether a client trusts the report: *"why does your assessment say 380 components when I
sent 400?"* An engine that silently drops twenty entries produces a cleaner-looking
score and an indefensible one.

**Checksums deduplicate within a tenant only.** The same public SBOM produces the same
checksum for every client who submits it, so a global unique constraint would leak the
fact that another tenant holds that document. `find_by_checksum` is org-scoped.

**Document scope is a first-class distinction.** `doc_author` and `doc_timestamp` are
properties of the document, not of each component. Probing for them per component would
report them absent across every entity and tell a supplier they failed a clause they
demonstrably met — a false negative the weighted score hides completely, because 0/855
looks exactly like a genuine gap.

---

## 4. Scoring output

```mermaid
erDiagram
    SUBMISSIONS ||--o{ LANE_RESULTS : "one per lane, always five"
    LANE_RESULTS ||--o{ FIELD_VERDICTS : "one per minimum element"
    GUIDELINE_VERSIONS ||--o{ MINIMUM_ELEMENTS : "pins"
    GUIDELINE_VERSIONS ||--o{ LANE_RESULTS : "scored against"
    MINIMUM_ELEMENTS ||--o{ FIELD_VERDICTS : "resolves"
    SUBMISSIONS ||--o{ CORRELATION_FINDINGS : "cross-BOM"

    GUIDELINE_VERSIONS {
        uuid id PK
        string ref "CERT-In Technical Guidelines on SBOM, QBOM and CBOM, AIBOM and HBOM"
        string version "2.0, unique"
        date published_on "2025-07-09"
        string checksum "of the encoded catalogue"
        string reviewed_by
        timestamptz created_at
    }

    MINIMUM_ELEMENTS {
        uuid id PK
        uuid guideline_version_id FK
        string lane
        string key "unique per lane per version"
        string label "the guideline's own field name"
        string clause "4.2(5), 8.4.1.2, 10.2(4)"
        enum tier "critical|standard|contextual"
        enum determinability "auto|enrich|human"
        string scope "entity|document"
        text rationale
        text consumer_action "mandatory when determinability=human"
        timestamptz created_at
    }

    LANE_RESULTS {
        uuid id PK
        uuid org_id FK
        uuid submission_id FK
        uuid guideline_version_id FK
        string lane
        numeric score "NULL for absent, timeout and not_applicable"
        enum verdict "pass|conditional|fail|lane_absent|lane_timeout|lane_not_applicable"
        int entity_count
        text detail "the sentence explaining the verdict"
        string engine_version "pinned so a re-score is distinguishable from engine drift"
        string inputs_hash
        timestamptz computed_at
        timestamptz created_at
    }

    FIELD_VERDICTS {
        uuid id PK
        uuid org_id FK
        uuid lane_result_id FK
        uuid minimum_element_id FK
        string element_key
        string clause
        enum verdict "present|absent|not_determinable"
        int populated
        int total "excludes out-of-scope assets from the denominator"
        numeric coverage
        numeric weight "tier weight applied"
        text detail
        text consumer_action "carried for not_determinable"
        timestamptz created_at
    }

    CORRELATION_FINDINGS {
        uuid id PK
        uuid org_id FK
        uuid submission_id FK
        string rule_key
        string severity "low|medium|high|critical"
        string clause
        text detail
        string left_ref "the entity on one side"
        string right_ref "and the other, so a reader can check"
        timestamptz created_at
    }
```

### Element inventory, as encoded

| Lane | Clause root | Elements | critical / standard / contextual | auto / enrich / human |
|---|---|---:|---|---|
| SBOM | s.4.2 | 21 | 7 / 8 / 6 | 15 / 4 / 2 |
| CBOM | s.8.4 | 20 | 11 / 6 / 3 | 19 / 0 / 1 |
| QBOM | s.8.5 | 10 | 3 / 5 / 2 | 9 / 0 / 1 |
| AIBOM | s.9.3 | 16 | 6 / 7 / 3 | 14 / 0 / 2 |
| HBOM | s.10.2 | 15 | 8 / 5 / 2 | 14 / 0 / 1 |
| **Total** | | **82** | **35 / 31 / 16** | **71 / 4 / 7** |

**`determinability` decides who is accountable for an absence.**

- `auto` — readable from the artifact. Absent means the supplier did not declare it.
- `enrich` — resolvable from an external feed (NVD, KEV, endoflife.date). Absent after
  enrichment is still a supplier gap, but the feed outage is reported distinctly.
- `human` — **the supplier could not have supplied it.** Criticality, s.4.2(12), is
  relative to the consuming deployment. Usage Restrictions, s.4.2(13), is a legal
  determination. Intended and Out-of-Scope Usage, s.9.3(15)–(16), are governance
  declarations. Scoring these as defects produces a report that is wrong in the client's
  favour; scoring them as compliant puts a green tick on a field nobody checked. Both end
  with a client failing a real audit while holding our assessment. So they leave the
  supplier score entirely, are reported in their own section, and each carries the
  `consumer_action` that resolves it.

Seven elements are `human` across the five lanes. The schema refuses to construct one
without a `consumer_action`, because a `not_determinable` verdict with no action reads as
a shrug.

---

## 5. Enrichment, identifiers and the agentic loop

```mermaid
erDiagram
    ORGS ||--o{ AGENT_RUNS : "commissions"
    SUBMISSIONS ||--o{ AGENT_RUNS : "about"
    AGENT_RUNS ||--o{ AGENT_EVIDENCE : "cites"
    AGENT_RUNS ||--o{ REGISTRY_PROPOSALS : "proposes"
    SUPPLIER_REGISTRY_ENTRIES ||--o| SUPPLIER_REGISTRY_ENTRIES : "succeeded by"
    ORGS ||--o{ IDENTIFIER_MAPPINGS : "holds"
    SUBMISSIONS ||--o{ IDENTIFIER_MAPPINGS : "resolves"

    CVES {
        uuid id PK
        string cve_id "unique"
        timestamptz published
        timestamptz modified
        text description
        string cvss_v31_vector
        float cvss_v31_score
        array cwe_ids
        timestamptz synced_at "staleness is reported, not hidden"
    }

    KEV_ENTRIES {
        uuid id PK
        string cve_id "unique, indexed"
        string vendor_project
        string product
        date added_on
        date due_date
        string known_ransomware
        timestamptz synced_at
    }

    EOL_RECORDS {
        uuid id PK
        string product_key
        string cycle "unique with product_key"
        date eol_date
        date support_end
        string latest_version
        date release_date
        string source "endoflife.date"
        timestamptz synced_at
    }

    ADVISORIES {
        uuid id PK
        string source "unique with ref"
        string ref
        text title
        string url
        date published
        array cve_ids
        timestamptz synced_at
    }

    AGENT_RUNS {
        uuid id PK
        uuid org_id FK
        uuid submission_id FK
        string kind "enrich|supplier|vex_evidence"
        string batch_key "batched per product, not per component"
        int hops "bounded by AGENT_MAX_HOPS=3"
        string verdict
        int tokens
        float inr_cost "per-run cost, ledger-verifiable"
        timestamptz created_at
    }

    AGENT_EVIDENCE {
        uuid id PK
        uuid agent_run_id FK
        int hop
        text query
        string source_url
        text snippet "including non-supporting evidence"
        timestamptz created_at
    }

    SUPPLIER_REGISTRY_ENTRIES {
        uuid id PK
        string purl_type "unique with namespace_or_name"
        string namespace_or_name
        string supplier_org "the Table 3 OrganizationName"
        string source "curated|proposed-accepted"
        float confidence
        string verified_by "a person, always"
        timestamptz verified_at
        uuid successor_id FK "renames and acquisitions"
        text note
    }

    REGISTRY_PROPOSALS {
        uuid id PK
        uuid org_id FK
        uuid agent_run_id FK
        string purl_type
        string namespace_or_name
        string proposed_supplier
        float confidence
        string status "pending|accepted|rejected"
        string reviewed_by
        timestamptz reviewed_at
        text reason
    }

    IDENTIFIER_MAPPINGS {
        uuid id PK
        uuid org_id FK
        uuid submission_id FK
        string component_name
        string purl
        string certin_id "pkg:supplier/OrganizationName/Component@Version"
        string supplier_org
        string source "registry|agent|manual|unresolved"
        float confidence
        string reviewed_by
        timestamptz created_at
    }
```

**Two tables for one fact, deliberately.** `registry_proposals` and
`supplier_registry_entries` hold the same shape of information and are separated by a
human. An agent researches a component's supplier, records what it read, how confident it
is and how many hops it took, and files a *proposal*. Nothing reaches the curated registry
without a review that writes `verified_by`. Merging them would make an agent's guess
indistinguishable from a verified fact the next time anyone read the table — and the Table
3 CERT-In identifier is built from `supplier_org`, so a wrong guess propagates into every
identifier the firm issues for that component.

**`agent_evidence` retains non-supporting snippets.** A reviewer confirming a proposal
needs to see what the agent read and rejected, not only what it kept. Evidence that only
ever agrees with the conclusion is not evidence.

**`synced_at` on every feed table.** An enrichment result derived from a four-week-old KEV
snapshot is reported as such. Feed staleness that is invisible becomes a client asking why
a KEV-listed CVE was not flagged.

---

## 5a. The corpus — retrieval, and the tenant boundary it depends on

```mermaid
erDiagram
    ORGS ||--o{ CORPUS_DOCUMENTS : "owns"
    ORGS ||--o{ CORPUS_CHUNKS : "owns"
    CORPUS_DOCUMENTS ||--o{ CORPUS_CHUNKS : "split into"
    ENGAGEMENTS ||--o{ CORPUS_DOCUMENTS : "written for"

    CORPUS_DOCUMENTS {
        uuid id PK
        uuid org_id FK
        string kind "past_assessment|policy|remediation_wording|house_style"
        string title
        string source_ref "so a reviewer can check a passage against its source"
        uuid engagement_id FK "used to EXCLUDE an engagement's own prior text"
        jsonb meta
        timestamptz created_at
    }

    CORPUS_CHUNKS {
        uuid id PK
        uuid org_id FK "denormalised: the scope must apply without a join"
        uuid document_id FK
        int ord
        text content "FACT-MASKED at ingest, never raw prose"
        text content_lower "the lexical half of hybrid search"
        vector embedding "vector(384) on Postgres, JSON list elsewhere"
        string embedding_model "provenance: which space this vector lives in"
        int embedding_dim
        int masked_count "evidence the guard ran"
        timestamptz created_at
    }
```

**`org_id` is denormalised onto the chunk deliberately.** The scope predicate has
to be applicable to the chunk query itself — requiring a join to know which tenant
a chunk belongs to is exactly how a scope gets forgotten. Both tables are
constrained anyway, so a join that is ever loosened still cannot cross the
boundary.

**`content` is fact-masked before the row is written.** The corpus holds the firm's
prose across every client it has ever assessed, and its purpose is to surface
passages from one engagement while drafting another. Percentages, clause
references, CVE identifiers and dates are replaced with typed placeholders at
ingest, so a figure belonging to one client cannot be retrieved into another's
report. `masked_count` records how many were removed — non-zero is healthy, and
zero across a whole corpus of past assessments would mean the masker silently
stopped matching.

**`embedding_model` and `embedding_dim` are recorded per chunk, not assumed
globally.** Change the embedder, leave the old vectors in place, and cosine
similarity still returns a perfectly plausible number computed over two unrelated
coordinate systems. The ranking looks fine and is noise. `assert_comparable`
refuses rather than letting that happen silently.

---

## 6. Assessment, review gate and VEX

```mermaid
erDiagram
    SUBMISSIONS ||--o{ ASSESSMENTS : "produces"
    ASSESSMENTS ||--o{ ASSESSMENT_SECTIONS : "composed of"
    USERS ||--o{ ASSESSMENTS : "authored"
    USERS ||--o{ ASSESSMENTS : "reviewed"
    USERS ||--o{ ASSESSMENTS : "approved"
    ORGS ||--o{ VEX_STATEMENTS : "authors"
    SUBMISSIONS ||--o{ VEX_STATEMENTS : "about"
    VEX_STATEMENTS ||--o{ CSAF_ADVISORIES : "published as"

    ASSESSMENTS {
        uuid id PK
        uuid org_id FK
        uuid submission_id FK
        string title
        string status "draft|in_review|approved|issued"
        uuid authored_by FK
        uuid reviewed_by FK
        uuid approved_by FK "must differ from authored_by"
        string s3_key
        int current_version
        timestamptz issued_at
        timestamptz created_at
    }

    ASSESSMENT_SECTIONS {
        uuid id PK
        uuid org_id FK
        uuid assessment_id FK
        int ord
        string section_type "executive_summary|lane_detail|consumer_determinations|roadmap|appendix"
        text content
        array field_verdict_ids "provenance: every figure traces to a verdict"
        array correlation_finding_ids
        timestamptz created_at
    }

    VEX_STATEMENTS {
        uuid id PK
        uuid org_id FK
        uuid submission_id FK
        string component_ref
        string cve_id "indexed"
        string status "not_affected|affected|fixed|under_investigation"
        text justification "required for not_affected"
        string authored_by
        string reviewed_by
        array evidence_refs
        timestamptz created_at
    }

    CSAF_ADVISORIES {
        uuid id PK
        uuid org_id FK
        uuid vex_statement_id FK
        string tracking_id
        jsonb doc "CSAF 2.0"
        timestamptz published_at
        timestamptz created_at
    }
```

**`vex_statements.status` is a plain `VARCHAR`, not a database enum**, and that is a
deliberate departure from every other status column here. Recommendation 7.1.6 names four
statuses and could gain a fifth in a future revision of the guideline; a schema migration
is a worse place to discover that than a validator. `services/vex/authoring.py` is the
authority and refuses anything outside the four.

**`assessment_sections.field_verdict_ids` is an array rather than a join table.** The ids
are read whole, always together with the section, and never queried in the reverse
direction. A join table would add a second read to every provenance lookup to answer a
question nobody asks.

**The review gate is three distinct columns.** An assessment cannot reach `issued` without
`approved_by` set, and `approved_by` may not equal `authored_by` — the assessor who ran
the assessment is the same pair of eyes however senior they are. Rank alone cannot express
that, so it is a constraint in the workflow service and a permission in the matrix.

---

## 7. Jobs and per-lane telemetry

```mermaid
erDiagram
    ORGS ||--o{ JOBS : "owns"
    ENGAGEMENTS ||--o{ JOBS : "scoped to"
    USERS ||--o{ JOBS : "requested"
    JOBS ||--o{ NODE_RUNS : "one per graph node"

    JOBS {
        uuid id PK
        uuid org_id FK
        uuid user_id FK
        uuid engagement_id FK
        uuid submission_id "indexed, not FK: survives submission deletion"
        enum job_type "assess|rescore|narrative x3|vex x2|generate_from_repo"
        enum status "queued|running|succeeded|failed|blocked_conformance"
        jsonb instructions
        string idempotency_key "globally unique"
        text error
        timestamptz terminal_at "set once; a conditional UPDATE enforces finality"
        timestamptz created_at
    }

    NODE_RUNS {
        uuid id PK
        uuid job_id FK
        string lane "null for non-lane nodes"
        string node "sbomLane, enrich, correlate, conformanceGate"
        int attempt
        string status "succeeded|failed|timeout"
        timestamptz started_at
        timestamptz finished_at
        float latency_ms
        text error
        timestamptz created_at
    }
```

**`node_runs` is what makes the fan-out auditable.** Two lane rows whose
`[started_at, finished_at]` intervals overlap prove the lanes ran concurrently; disjoint
intervals would mean a graph that only reads as parallel. `latency_ms` per lane is also the
source of the p95 figures in `dist/scale-report.md`.

**`blocked_conformance` is a job status, not an error.** A citation that does not resolve
to the pinned guideline version stops the render deliberately. It is a refusal, and
recording it as a failure would make a working safety mechanism look like a bug.

---

## 8. Whole-schema overview

```mermaid
graph TB
    subgraph tenancy["Tenancy — every scoped table carries org_id"]
        ORGS[orgs]
        USERS[users]
        CLIENTS[clients]
        ENG[engagements]
        AUDIT[audit_events]
    end

    subgraph intake["Intake — conservation is provable"]
        SUB[submissions]
        DOC[bom_documents]
        RAW[raw_entries]
    end

    subgraph pinned["Pinned guideline — the factual basis"]
        GV[guideline_versions]
        ME[minimum_elements]
    end

    subgraph scoring["Scoring — deterministic, no model involved"]
        LR[lane_results]
        FV[field_verdicts]
        CF[correlation_findings]
    end

    subgraph knowledge["Knowledge base — feeds, with staleness"]
        CVE[cves]
        KEV[kev_entries]
        EOL[eol_records]
        ADV[advisories]
    end

    subgraph agentic["Agentic — proposes, never decides"]
        AR[agent_runs]
        AE[agent_evidence]
        RP[registry_proposals]
        SRE[supplier_registry_entries]
        IM[identifier_mappings]
    end

    subgraph output["Output — provenance to every figure"]
        ASM[assessments]
        ASEC[assessment_sections]
        VEX[vex_statements]
        CSAF[csaf_advisories]
    end

    subgraph ops["Operations"]
        JOB[jobs]
        NR[node_runs]
    end

    ORGS --> USERS
    ORGS --> CLIENTS
    ORGS --> ENG
    ORGS --> AUDIT
    CLIENTS --> ENG
    ENG --> SUB
    SUB --> DOC
    DOC --> RAW
    SUB --> LR
    GV --> ME
    GV --> LR
    LR --> FV
    ME --> FV
    SUB --> CF
    SUB --> AR
    AR --> AE
    AR --> RP
    RP -.human review.-> SRE
    SRE --> IM
    SUB --> IM
    KEV --> LR
    CVE --> LR
    EOL --> LR
    SUB --> ASM
    ASM --> ASEC
    FV -.provenance.-> ASEC
    CF -.provenance.-> ASEC
    SUB --> VEX
    VEX --> CSAF
    ENG --> JOB
    JOB --> NR

    style pinned fill:#fff8e1,stroke:#f9a825
    style agentic fill:#fce4ec,stroke:#c2185b
    style scoring fill:#e8f5e9,stroke:#2e7d32
```

---

## 9. Indexes and constraints that carry a rule

| Object | Table | Why it exists |
|---|---|---|
| `uq_users_org_id_email` | `users` | The same person may hold accounts at two advisory firms. Email is unique *per org*, not globally. |
| `uq_users_google_sub` | `users` | One Google identity maps to one account, globally — otherwise OAuth sign-in is ambiguous. |
| `uq_bom_documents_org_id_checksum` | `bom_documents` | Deduplicates a resubmitted document *within* a tenant. Global uniqueness would leak that another tenant holds the same public SBOM. |
| `uq_jobs_idempotency_key` | `jobs` | A retried commit must not enqueue a second assessment. |
| `ix_jobs_live` — partial, `WHERE terminal_at IS NULL` | `jobs` | The worker's hot query is "what is still running in this tenant"; a full index would be mostly dead rows. |
| `ix_lane_results_submission_id_lane` | `lane_results` | Every read is "the five lanes of this submission". |
| `ix_field_verdicts_lane_result_id_verdict` | `field_verdicts` | The gap register reads one lane's *unmet* elements; filtering by verdict is the query, and clause ordering is applied after. |
| `uq_minimum_elements_version_lane_key` | `minimum_elements` | Two elements claiming one key in a lane means one of them is wrong. |
| `uq_guideline_versions_version` | `guideline_versions` | One row per published guideline version, ever. |
| `uq_supplier_registry_type_namespace` | `supplier_registry_entries` | A component resolves to exactly one supplier organisation. |
| `ix_audit_events_org_id_created_at` | `audit_events` | Audit review is always "this tenant, this window". |

---

## 10. Migrations

| Revision | Adds |
|---|---|
| `0001_foundation` | `orgs`, `users`, `jobs`, `node_runs`, `guideline_versions`, and every native enum type |
| `0002_submissions` | `clients`, `engagements`, `submissions`, `bom_documents`, `lane_results`, `field_verdicts` |
| `0003_auth` | MFA columns, Google identity, the partial index on live jobs |
| `0004_ingestion_catalogue` | `raw_entries`, `minimum_elements`, element scope |
| `0005_correlation` | `correlation_findings` |
| `0006_enrichment_identifiers` | `cves`, `kev_entries`, `eol_records`, `advisories`, `agent_runs`, `agent_evidence`, `supplier_registry_entries`, `registry_proposals`, `identifier_mappings` |
| `0007_vex_assessments` | `vex_statements`, `csaf_advisories`, `assessments`, `assessment_sections` |
| `0008_generation_job_type` | `generate_from_repo` on the `job_type` enum |
| `0009_corpus_retrieval` | `corpus_documents`, `corpus_chunks`, the `vector` extension and the full-text index |

Every migration is hand-reviewed. `tests/test_migrations.py` asserts that
`upgrade head → downgrade base → upgrade head` round-trips, that every native enum type
created on the way up is dropped on the way down, and that tables drop in reverse
dependency order.

**Migration 0008 is the awkward one and documents why.** PostgreSQL has no `DROP VALUE`,
so removing an enum value means rebuilding the type. The downgrade renames the old type
aside, recreates it without the new value, and casts the column across — which *fails
loudly* if any row still carries the removed value. That is the correct outcome: silently
dropping those rows' type would corrupt the job log.

---

## 11. Retention and data protection

| Concern | Treatment |
|---|---|
| BOM payloads | Object storage, `ap-south-1`, presigned access only, SSE-KMS with a per-client key. A BOM is an architecture disclosure and this system holds many suppliers' at once. |
| Retention | `SUBMISSION_RETENTION_DAYS`, default 1095 (three years) — the assessment must outlive the audit that relies on it. |
| Logs | `utils/redaction.py` runs as the **last** structlog processor before rendering, so nothing a later processor adds escapes it. No internal hostname, filesystem path, email or secret from a BOM reaches log storage. Logs outlive engagements. |
| MFA secrets | `users.mfa_secret` is never logged and never returned by any endpoint. |
| Audit metadata | `audit_events.meta` carries identifiers and outcomes only. Component names are supplier-controlled text and a component list is an architecture disclosure. |

---

*Generated from `backend/app/models/` at 30 tables. Guideline basis: CERT-In v2.0,
09.07.2025. See [PRODUCT_SPECIFICATION.md](PRODUCT_SPECIFICATION.md) and
[ARCHITECTURE.md](ARCHITECTURE.md).*
