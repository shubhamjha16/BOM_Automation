"""The governance pack, generated from an organisation's actual gaps.

**Generated from the scorecard, not from a template.** A pack that ships every
document regardless of position is a template with a covering letter: it tells an
organisation nothing about what they specifically lack, and the reader has to
work out which parts apply. Generating from the S19 gaps means the pack answers
"what do we not have?" — which is the question that produced it.

Each artifact names the clause it satisfies and the gap it closes, so a reader
can trace a document back to the assessment that called for it.

**These are drafts for review, not legal instruments.** The procurement clause in
particular needs counsel: it is contract language, and this product is explicit
elsewhere that it does not issue legal opinions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.services.maturity.roadmap import Phase
from app.services.maturity.scorecard import Scorecard

REVIEW_NOTICE = (
    "This is a generated draft for review, not a legal instrument. It reflects the "
    "gaps found in the maturity assessment; it has not been reviewed by counsel and "
    "this product does not issue legal or regulatory opinions."
)


@dataclass(frozen=True, slots=True)
class Artifact:
    key: str
    title: str
    clause: str
    #: The activity whose absence called for this document.
    closes_gap: str
    body: str

    def as_row(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "title": self.title,
            "clause": self.clause,
            "closes_gap": self.closes_gap,
            "body": self.body,
            "notice": REVIEW_NOTICE,
        }


def _sbom_policy(organisation: str) -> str:
    return f"""# SBOM policy — {organisation}

## Purpose
Every software product this organisation builds or procures is accompanied by a
Bill of Materials meeting the CERT-In minimum elements (s.4.2).

## Scope
All software delivered to or operated by {organisation}, including third-party
and open-source components.

## Requirements
1. An SBOM is produced for every release, update and patch (s.2.3).
2. It is generated within the build pipeline, not by hand (rec. 7.2.2).
3. It carries all 21 minimum elements of s.4.2 where they are derivable from the
   artifact. Criticality (4.2(12)) and Usage Restrictions (4.2(13)) are consumer
   determinations recorded separately by this organisation.
4. Components are identified by the CERT-In unique identifier of Table 3.
5. SBOMs are retained for the life of the deployment plus three years.

## Accountability
The accountable owner is named in the RACI matrix accompanying this policy.
"""


def _procurement_clause(organisation: str) -> str:
    return f"""# Procurement clause — SBOM provision (implements 3.3.1.4)

The following language is offered for inclusion in {organisation}'s supply
agreements. **It requires review by counsel before use.**

---

**Bill of Materials.** The Supplier shall provide, at no additional charge and
for each release, update or patch of the Software, a Bill of Materials in
CycloneDX or SPDX format conforming to the minimum elements set out in section
4.2 of the CERT-In *Technical Guidelines on SBOM, QBOM & CBOM, AIBOM and HBOM*
(v2.0, 09.07.2025), including for each component: name, version, supplier,
licence, origin, dependencies and cryptographic hash.

**Vulnerability disclosure.** The Supplier shall provide a VEX statement for each
vulnerability disclosed against a declared component, using one of the four
statuses defined in recommendation 7.1.6. A statement of `not_affected` shall
carry a written justification.

**Currency.** The Bill of Materials shall be provided within [N] days of each
release and shall reflect the software as delivered.

**Audit.** {organisation} may verify the Bill of Materials against the delivered
artifact. A material discrepancy between declared and delivered components shall
be remedied within [N] days.

---

{REVIEW_NOTICE}
"""


#: Held as data rather than as a markdown blob, so no source line has to be
#: wrapped — wrapping one would break the table for the reader.
_RACI_ROWS: tuple[tuple[str, str, str, str, str], ...] = (
    ("Producing SBOMs for our own software", "Engineering", "Head of Engineering",
     "Security", "Procurement"),
    ("Requiring SBOMs from suppliers", "Procurement", "CISO", "Legal", "Engineering"),
    ("Assessing supplier submissions", "Security", "CISO", "Engineering", "Procurement"),
    ("Authoring VEX statements", "Security", "CISO", "Engineering", "Customers"),
    ("Recording consumer determinations (4.2(12)–(13))", "Engineering",
     "Head of Engineering", "Legal, Security", "—"),
    ("Maintaining this policy set", "Security", "CISO", "Legal", "All"),
)


def _raci(organisation: str) -> str:
    table = "\n".join("| " + " | ".join(row) + " |" for row in _RACI_ROWS)
    return f"""# RACI — software supply-chain security ({organisation}), per §5.1

| Activity | Responsible | Accountable | Consulted | Informed |
|---|---|---|---|---|
{table}

§5.1(d) requires a body accountable for supply-chain security. Name it here,
with its chair and meeting cadence — an unnamed accountability is not one.
"""


def _vex_playbook(organisation: str) -> str:
    return f"""# VEX and incident-response playbook ({organisation}), per 3.3.3.2

## When a vulnerability is disclosed against a declared component

1. **Determine reachability.** Is the vulnerable code path reachable in our
   configuration? Record what was checked, not only the conclusion.
2. **Assign one of four statuses** (rec. 7.1.6). There is no fifth:
   `not_affected`, `affected`, `fixed`, `under_investigation`.
3. **Publish `under_investigation` immediately** if the determination will take
   time. Silence reads as "not affected" to anyone waiting, and an absence of
   evidence is not a clearance.
4. **A `not_affected` determination requires a written justification** that a
   reader can check — the reasoning, not the verdict.
5. **Publish as CSAF** so a consumer's tooling can act on it without reading
   prose.

## Who decides
The status is an analyst determination. Evidence may be assembled by tooling; the
determination is made by a named person and recorded against their name.

## Escalation
A KEV-listed vulnerability in a component we ship is escalated to the accountable
owner within one working day.
"""


def _installation_checklist(organisation: str) -> str:
    return f"""# Secure installation and operation checklist ({organisation}), per 3.3.2.1

- [ ] Verify the delivered artifact against the hash declared in the SBOM.
- [ ] Confirm the SBOM covers the version actually being installed.
- [ ] Record the deployment's consumer determinations: Criticality (4.2(12)) and
      Usage Restrictions (4.2(13)) — neither can be supplied by the vendor.
- [ ] Confirm no component is past its declared end-of-life (4.2(11)).
- [ ] Confirm cryptographic configuration: no deprecated protocol versions or
      cipher suites (s.8.4.2.2), no expired certificates.
- [ ] Apply least-privilege service accounts.
- [ ] Register the deployment for re-assessment on every release (s.2.3).
"""


def _access_rules(organisation: str) -> str:
    return f"""# BOM access control and distribution ({organisation}), per §5.3

**A Bill of Materials is an architecture disclosure.** It names internal
services, versions and dependencies, and it is exactly what an attacker would
ask for.

1. Stored BOMs are access-controlled and scoped to the engagement they belong to.
2. Distribution outside {organisation} requires the accountable owner's approval.
3. BOMs are encrypted at rest with per-client keys.
4. Logs and telemetry never carry BOM content — identifiers and counts only.
5. Retention follows the engagement's data policy; expired submissions are
   deleted from primary storage and backups.
6. A supplier's BOM is not shared with another supplier.
"""


BUILDERS: dict[str, tuple[str, str, Any]] = {
    "sbom_policy": ("SBOM policy", "3.3.1.3", _sbom_policy),
    "procurement_clause": ("Procurement clause", "3.3.1.4", _procurement_clause),
    "raci": ("RACI matrix", "5.1(d)", _raci),
    "vex_playbook": ("VEX and incident-response playbook", "3.3.3.2", _vex_playbook),
    "installation_checklist": (
        "Secure installation and operation checklist",
        "3.3.2.1",
        _installation_checklist,
    ),
    "access_rules": ("BOM access control and distribution", "5.3", _access_rules),
}

#: Which artifact closes which activity. An organisation gets the documents its
#: own gaps call for, not the whole shelf.
GAP_TO_ARTIFACT: dict[str, str] = {
    "generate_sbom": "sbom_policy",
    "inventory_dependencies": "sbom_policy",
    "pin_dependencies": "sbom_policy",
    "procurement_clauses": "procurement_clause",
    "governance_body": "raci",
    "incident_playbook": "vex_playbook",
    "vex_history": "vex_playbook",
    "secure_installation": "installation_checklist",
    "access_controls_on_boms": "access_rules",
}


def build_pack(
    scorecard: Scorecard, *, organisation: str = "your organisation"
) -> list[Artifact]:
    """The documents this organisation's gaps actually call for."""
    wanted: dict[str, str] = {}
    for gap in scorecard.gaps:
        artifact_key = GAP_TO_ARTIFACT.get(gap.activity_key)
        if artifact_key and artifact_key not in wanted:
            wanted[artifact_key] = gap.activity_key

    artifacts: list[Artifact] = []
    for key, closes in wanted.items():
        title, clause, builder = BUILDERS[key]
        artifacts.append(
            Artifact(
                key=key,
                title=title,
                clause=clause,
                closes_gap=closes,
                body=builder(organisation),
            )
        )
    return artifacts


def required_for_phase(phase: Phase) -> set[str]:
    """Every artifact a phase's activities call for.

    Used to check the S20 exit condition: a START-phase organisation's pack must
    contain every document that phase requires.
    """
    from app.services.maturity.roadmap import by_phase

    return {
        GAP_TO_ARTIFACT[activity.key]
        for activity in by_phase(phase)
        if activity.key in GAP_TO_ARTIFACT
    }


def pack_report(artifacts: list[Artifact]) -> dict[str, Any]:
    return {
        "count": len(artifacts),
        "notice": REVIEW_NOTICE,
        "artifacts": [artifact.as_row() for artifact in artifacts],
    }
