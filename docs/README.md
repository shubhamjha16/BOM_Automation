# Documentation

Four documents. Each is written from the code as it actually stands — the table
counts, element inventories, clause provenance and performance figures here are
extracted from the running system, not from a plan.

| Document | Read it for |
|---|---|
| [PRODUCT_SPECIFICATION.md](PRODUCT_SPECIFICATION.md) | What the product does and refuses to do. The three-state verdict model, scoring arithmetic and its three non-arithmetic overrides, roles, workflows, quotas, API surface, and a plainly-stated limitations section. |
| [ARCHITECTURE.md](ARCHITECTURE.md) | How it is built. System context, containers, the assessment graph and its fan-out, the scoring pipeline, tenancy enforcement, observability, deployment. 15 diagrams. |
| [DATA_MODEL.md](DATA_MODEL.md) | The schema. 30 tables across 8 entity-relationship diagrams, every index and the rule it carries, migration history, retention. |
| [COMPLIANCE_MATRIX.md](COMPLIANCE_MATRIX.md) | Clause-by-clause mapping to CERT-In v2.0. All 82 minimum elements, the correlation rules, the s.3.3 maturity activities, and the provenance of every clause reference. |
| [SCREENSHOTS.md](SCREENSHOTS.md) | The console running, annotated. Nine screens from a real `make demo` — every figure on them came from the scoring engine, not from mock data. |

## Guideline basis

*CERT-In Technical Guidelines on SBOM, QBOM & CBOM, AIBOM and HBOM*,
**v2.0, 09.07.2025**.

**Check the provenance before quoting a clause number.** 26 of the 101 clause
references in this product are confirmed against the published guideline; the
other 75 are encoded from the tables and marked provisional.
[COMPLIANCE_MATRIX.md](COMPLIANCE_MATRIX.md) marks each one, and
`make catalogue-audit` regenerates the full worksheet into
`dist/catalogue-audit.md`.

## Regenerating the published figures

Every number in these documents that describes measured behaviour comes from a
command you can run:

```bash
make catalogue-audit   # clause provenance — 26/101 confirmed
make scale             # 50,000-component budget and per-lane p95
make self-bom          # this repository's own SBOM
make test              # 806 backend cases, 36 frontend
```

## Diagrams

Every diagram is Mermaid, rendered natively by GitHub. All 30 were parsed with
`mermaid.parse` before commit, because a diagram that silently fails to render is
worse than no diagram — the page looks complete and the reader learns nothing.
