"""Assessment sections, built from what the engine computed.

**The drafter restates; it never produces.** Every figure here comes from a lane
result or a field verdict and passes `figureProvenanceValidator`; every clause
passes the S8 gate. That is why these sections are assembled in code rather than
generated: the narrative sprint (S15) is about *what a procurement reader needs
to see*, and a model's contribution is prose polish over a structure that is
already correct — not the structure itself.

**Ordered by tier, not by clause number.** A reader asked for "the top three
gaps" will read the first three. Clause order would put 4.2(1) Component Name
above 4.2(21) CERT-In Identifier, which inverts the priority: the first is
almost always present and the second is the one that fails procurement.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

TIER_RANK = {"critical": 0, "standard": 1, "contextual": 2}


@dataclass(frozen=True, slots=True)
class Section:
    ord: int
    section_type: str
    title: str
    body: str
    #: The provenance chain: what this section was written from.
    field_verdict_keys: tuple[str, ...] = ()
    correlation_rule_keys: tuple[str, ...] = ()

    def as_row(self) -> dict[str, Any]:
        return {
            "ord": self.ord,
            "section_type": self.section_type,
            "title": self.title,
            "content": self.body,
            "field_verdict_ids": list(self.field_verdict_keys),
            "correlation_finding_ids": list(self.correlation_rule_keys),
        }


@dataclass(slots=True)
class AssessmentInput:
    """Everything the sections are written from. Nothing else is consulted."""

    submission_id: str
    overall_score: float | None
    lane_results: list[Any] = field(default_factory=list)
    correlation_findings: list[Any] = field(default_factory=list)


def _gaps(lane: Any) -> list[dict[str, Any]]:
    return [
        row
        for row in (getattr(lane, "field_results", None) or [])
        if str(row.get("verdict")) == "absent"
    ]


def _ranked_gaps(assessment: AssessmentInput) -> list[tuple[str, dict[str, Any]]]:
    """Every gap across every lane, worst first.

    Tier first, then coverage: a critical field at 0% outranks a critical field
    at 60%, and both outrank anything standard.
    """
    ranked: list[tuple[str, dict[str, Any]]] = []
    for lane in assessment.lane_results:
        for row in _gaps(lane):
            ranked.append((lane.lane, row))
    return sorted(
        ranked,
        key=lambda item: (
            TIER_RANK.get(str(item[1].get("tier")), 3),
            item[1].get("coverage") if item[1].get("coverage") is not None else 0.0,
            str(item[1].get("clause")),
        ),
    )


def executive_summary(assessment: AssessmentInput) -> Section:
    """Written for a procurement reader with no security background.

    States the verdict, then the three gaps that matter, in plain terms. No
    jargon that a reader would have to look up, and no figure the engine did not
    compute.
    """
    lanes = assessment.lane_results
    scored = [lane for lane in lanes if lane.score is not None]
    absent = [lane for lane in lanes if str(lane.verdict) == "lane_absent"]

    top = _ranked_gaps(assessment)[:3]
    score_text = (
        f"{assessment.overall_score}%" if assessment.overall_score is not None else "not scored"
    )

    parts = [
        f"This submission scored {score_text} against the CERT-In minimum elements.",
    ]
    if scored:
        detail = ", ".join(f"{lane.lane.upper()} {lane.score}%" for lane in scored)
        parts.append(f"Lanes assessed: {detail}.")
    if absent:
        parts.append(
            f"{len(absent)} bill(s) of materials were expected and not supplied "
            f"({', '.join(lane.lane.upper() for lane in absent)}), which is itself a "
            "finding rather than an absence of information."
        )

    if top:
        parts.append("The three gaps requiring attention first:")
        for index, (lane, row) in enumerate(top, start=1):
            populated, total = row.get("populated", 0), row.get("total", 0)
            parts.append(
                f"  {index}. {row.get('label') or row.get('element_key')} "
                f"({lane.upper()}, clause {row.get('clause')}) — declared on "
                f"{populated} of {total} entries."
            )
    else:
        parts.append("No unmet minimum elements were found in the lanes assessed.")

    parts.append(
        "This is a conformance assessment against a published technical guideline. "
        "It is not a legal opinion, and a passing score states that the declaration "
        "is complete, not that the software is secure."
    )

    return Section(
        ord=1,
        section_type="executive_summary",
        title="Executive summary",
        body="\n".join(parts),
        field_verdict_keys=tuple(f"{lane}:{row.get('element_key')}" for lane, row in top),
    )


def lane_findings(assessment: AssessmentInput) -> list[Section]:
    sections: list[Section] = []
    for index, lane in enumerate(assessment.lane_results, start=2):
        gaps = _gaps(lane)
        if str(lane.verdict) == "lane_not_applicable":
            body = (
                f"The {lane.lane.upper()} lane is not enabled for this engagement and "
                "is excluded from the overall score. This is different from a bill of "
                "materials that was expected and not supplied."
            )
        elif str(lane.verdict) == "lane_absent":
            body = (
                f"No {lane.lane.upper()} was supplied. This is reported as a finding: "
                "the engagement expects one, and its absence means the corresponding "
                "declarations have not been made."
            )
        else:
            body = (
                f"Scored {lane.score}% across {lane.entity_count} entries. "
                f"{lane.detail} "
                f"{len(gaps)} minimum element(s) are unmet."
            )
        sections.append(
            Section(
                ord=index,
                section_type=f"lane_{lane.lane}",
                title=f"{lane.lane.upper()} findings",
                body=body,
                field_verdict_keys=tuple(f"{lane.lane}:{row.get('element_key')}" for row in gaps),
            )
        )
    return sections


def consumer_determinations(assessment: AssessmentInput, ord: int) -> Section:
    """Its own section, never mixed into the supplier score."""
    rows: list[tuple[str, dict[str, Any]]] = []
    for lane in assessment.lane_results:
        for row in getattr(lane, "field_results", None) or []:
            if str(row.get("verdict")) == "not_determinable":
                rows.append((lane.lane, row))

    lines = [
        "The following elements cannot be established from a bill of materials at "
        "all. They are excluded from the supplier's score and are not reported as "
        "met — each requires a determination by your own organisation.",
        "",
    ]
    for lane, row in rows:
        lines.append(
            f"{row.get('clause')} {row.get('label') or row.get('element_key')} ({lane.upper()})"
        )
        lines.append(f"    Action required: {row.get('consumer_action')}")

    return Section(
        ord=ord,
        section_type="consumer_determinations",
        title="Consumer determinations",
        body="\n".join(lines),
        field_verdict_keys=tuple(f"{lane}:{row.get('element_key')}" for lane, row in rows),
    )


def remediation_roadmap(assessment: AssessmentInput, ord: int) -> Section:
    """Prioritised, with the clause each step rests on.

    A roadmap without clause references is a to-do list; the supplier needs to
    know which requirement each step satisfies, because that is what they will be
    audited against.
    """
    ranked = _ranked_gaps(assessment)
    lines = [
        "Remediation steps in priority order. Each states the clause it satisfies.",
        "",
    ]
    for index, (lane, row) in enumerate(ranked, start=1):
        populated, total = row.get("populated", 0), row.get("total", 0)
        tier = str(row.get("tier")).upper()
        label = row.get("label") or row.get("element_key")
        lines.append(f"{index}. [{tier}] {label} — {lane.upper()} clause {row.get('clause')}")
        lines.append(
            f"    Currently declared on {populated} of {total}. {row.get('detail') or ''}".rstrip()
        )

    if assessment.correlation_findings:
        lines.append("")
        lines.append("Cross-document findings:")
        for finding in assessment.correlation_findings:
            lines.append(f"  - clause {finding.clause}: {finding.detail}")

    return Section(
        ord=ord,
        section_type="remediation_roadmap",
        title="Remediation roadmap",
        body="\n".join(lines),
        field_verdict_keys=tuple(f"{lane}:{row.get('element_key')}" for lane, row in ranked),
        correlation_rule_keys=tuple(
            finding.rule_key for finding in assessment.correlation_findings
        ),
    )


def field_appendix(assessment: AssessmentInput, ord: int) -> Section:
    """Every field verdict, so nothing in the summary is unverifiable."""
    lines: list[str] = []
    keys: list[str] = []
    for lane in assessment.lane_results:
        rows = getattr(lane, "field_results", None) or []
        if not rows:
            continue
        lines.append(f"{lane.lane.upper()}")
        for row in rows:
            lines.append(
                f"  {row.get('clause'):<10} {row.get('label') or row.get('element_key'):<42} "
                f"{row.get('populated')}/{row.get('total'):<6} {row.get('verdict')}"
            )
            keys.append(f"{lane.lane}:{row.get('element_key')}")
        lines.append("")

    return Section(
        ord=ord,
        section_type="field_appendix",
        title="Appendix: every field verdict",
        body="\n".join(lines),
        field_verdict_keys=tuple(keys),
    )


def build_sections(assessment: AssessmentInput) -> list[Section]:
    """The full assessment, in reading order."""
    sections = [executive_summary(assessment)]
    sections.extend(lane_findings(assessment))
    next_ord = len(sections) + 1
    sections.append(consumer_determinations(assessment, next_ord))
    sections.append(remediation_roadmap(assessment, next_ord + 1))
    sections.append(field_appendix(assessment, next_ord + 2))
    return sections
