# Catalogue audit worksheet

Every clause reference this product can place in front of a client, with its provenance. **Anchored** means the ordinal has been confirmed against the published CERT-In guideline v2.0 (09.07.2025). **Provisional** means it was encoded from the table and has not been.

**113 of 120 clause references confirmed (94.17%).** The remainder are provisional. That number is published rather than rounded up, because a provisional ordinal presented as confirmed is the one defect that would discredit every assessment issued.

| Source | Confirmed | Total | % |
| --- | ---: | ---: | ---: |
| aibom | 19 | 19 | 100.0% |
| cbom | 30 | 30 | 100.0% |
| correlation | 5 | 5 | 100.0% |
| hbom | 20 | 20 | 100.0% |
| qbom | 11 | 11 | 100.0% |
| roadmap | 7 | 14 | 50.0% |
| sbom | 21 | 21 | 100.0% |

## Rows awaiting confirmation

| Source | Key | Element | Clause |
| --- | --- | --- | --- |
| roadmap | pin_dependencies | Pin dependencies to exact versions | s.3.3.1.2 |
| roadmap | generate_sbom | Generate an SBOM for each product | s.3.3.1.3 |
| roadmap | vulnerability_scanning | Scan dependencies for known vulnerabilities | s.3.3.2.2 |
| roadmap | access_controls_on_boms | Apply access controls to stored BOMs | s.3.3.2.6 |
| roadmap | training | Train development teams on SSDLC practice | s.7.2.15 |
| roadmap | vex_history | Maintain a VEX history for disclosed vulnerabilities | s.3.3.3.1 |
| roadmap | continuous_monitoring | Monitor supplier conformance continuously | s.3.3.3.3 |

## Instrument findings

No stale anchors and no duplicated ordinals within a source. These are mechanical checks only — they do not substitute for the re-derivation.

## What this document is not

It is not the audit. Re-deriving a clause from the published guideline is a person reading a PDF, and no instrument can do it. Anything here that claimed otherwise would be manufacturing the assurance it is meant to measure.
