# BOM fixtures — provenance

**Read this before treating a fixture as evidence.** The sprint plan asks for
"real output from Syft, Trivy and cdxgen". Two of those three tools are not
installed on the machine this was built on, and the difference between *captured*
and *authored* output matters: a hand-written fixture tests the parser against
what we believe a tool emits, not against what it actually emits.

So each file states which it is.

## Genuinely captured tool output

| File | Tool | Notes |
|---|---|---|
| `cyclonedx/cdxgen-backend-1.4.json` | cdxgen 11.11.0 | Real run over `backend/`, `--spec-version 1.4` |
| `cyclonedx/cdxgen-backend-1.5.json` | cdxgen 11.11.0 | Same, 1.5 |
| `cyclonedx/cdxgen-backend-1.6.json` | cdxgen 11.11.0 | Same, 1.6 |

These carry cdxgen's real quirks — sparse licences, absent suppliers, its own
`metadata.tools` shape — which is exactly why the self-conformance score is low
and honest.

## Authored to the published specification

| File | Shaped after | Notes |
|---|---|---|
| `spdx/syft-shaped-SPDX-2.2.json` | Syft | SPDX 2.2 JSON, authored from the spec |
| `spdx/syft-shaped-SPDX-2.3.json` | Syft | SPDX 2.3 JSON |
| `spdx/trivy-shaped-SPDX-2.2.spdx` | Trivy | SPDX 2.2 tag-value |
| `spdx/trivy-shaped-SPDX-2.3.spdx` | Trivy | SPDX 2.3 tag-value |
| `spdx/truncated-mid-text.spdx` | — | Cut mid-`<text>`, for the byte-offset test |

Named `*-shaped-*` rather than `syft-*` so nobody later mistakes them for
captured output. They deliberately include the imperfections that matter to
scoring: `NOASSERTION` licences and suppliers, packages with no SPDXID, and
dependency relationships expressed in both directions (`DEPENDS_ON` and
`DEPENDENCY_OF`).

**Outstanding**: capture real Syft and Trivy output on a machine that has them
and replace the four authored files. Until then, a parser bug that only shows up
against a real tool's output would not be caught here — that is the known limit
of this fixture set, and it is the reason the table above exists.
