"""The catalogue audit instrument — S20.

The catalogue is the product's factual basis. Every verdict this system issues
cites a clause, and one wrong ordinal discredits every assessment the firm has
ever sent out. So the clause numbers are not merely encoded; each one carries its
**provenance**, and the two kinds are never conflated:

``ANCHORED``
    The clause number has been confirmed against the published guideline.

``PROVISIONAL``
    The element was encoded from the table and its ordinal has not yet been
    re-derived from the PDF.

**This module does not perform the audit and cannot.** Re-deriving a clause from
the published document is a person reading a PDF; nothing here can do it, and any
code claiming to would be manufacturing the assurance it is supposed to measure —
the same failure §11 forbids when it refuses to score `not_determinable` as
compliant, and the same one S19 forbids when it refuses to let an attested
activity count as evidenced.

What this module does is produce the **worksheet** that makes the audit possible
and its state visible: every clause reference in the product, in one place, with
its provenance, so the fraction still unconfirmed is a number on a page rather
than a thing nobody tracks. When the assessor finds a discrepancy, it is fixed
and becomes a permanent case in ``tests/test_catalogue.py``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, cast

from app.configs.envConfig import ALL_LANES, Lane
from app.services.catalogue import aibom, cbom, hbom, qbom, sbom
from app.services.catalogue.loader import get_catalogue
from app.services.correlate.engine import RULES
from app.services.maturity.roadmap import ACTIVITIES


class Provenance(StrEnum):
    ANCHORED = "anchored"
    PROVISIONAL = "provisional"


class Notation(StrEnum):
    """How a clause reference is written, which is not a cosmetic distinction.

    The guideline uses two: a **section** number (``8.4.1.2``, ``3.3.1.4``) and a
    **table ordinal** — a row counted off a table inside a section, written
    ``4.2(5)``. They are checked differently. Ordinals must run 1..n with no gap,
    because a gap means a row was dropped in transcription; section numbers must
    only be monotonic, because a table may legitimately begin at ``.2``.

    Mixing the two inside one lane is where the mistakes live: ``10.2(4)`` and
    ``10.2.4`` are different references that differ by one character.
    """

    SECTION = "section"
    TABLE_ORDINAL = "table_ordinal"


def notation_of(clause: str) -> Notation:
    return Notation.TABLE_ORDINAL if "(" in clause else Notation.SECTION


def _sort_key(clause: str) -> tuple[int, ...]:
    """Dotted numbers compared numerically, so ``8.4.1.10`` follows ``8.4.1.9``."""
    digits = clause.replace("(", ".").replace(")", "")
    return tuple(int(part) for part in digits.split(".") if part.isdigit())


#: The anchored map for each lane, held beside that lane's catalogue rather than
#: copied here — a second list of anchors would drift from the first.
ANCHOR_MAPS: dict[str, dict[str, str]] = {
    "sbom": sbom.ANCHORED_CLAUSES,
    "aibom": aibom.ANCHORED_CLAUSES,
    "cbom": cbom.ANCHORED_CLAUSES,
    "qbom": qbom.ANCHORED_CLAUSES,
    "hbom": hbom.ANCHORED_CLAUSES,
}

#: Roadmap activities whose clause numbers are confirmed against s.3.3. The
#: maturity table is audited on the same terms as the five BOM tables: §S19's
#: scorecard cites these clauses to a client, so an unconfirmed ordinal there is
#: exactly as damaging as an unconfirmed one in the SBOM table.
ROADMAP_ANCHORED: frozenset[str] = frozenset(
    {"3.3.1.1", "3.3.1.4", "3.3.2.1", "3.3.2.5", "3.3.3.2", "2.3", "5.1(d)"}
)


@dataclass(frozen=True, slots=True)
class AuditRow:
    """One clause reference, and everything the assessor needs to check it."""

    source: str
    key: str
    label: str
    clause: str
    provenance: Provenance

    @property
    def confirmed(self) -> bool:
        return self.provenance is Provenance.ANCHORED


def _lane_rows(lane: Lane) -> list[AuditRow]:
    anchored = ANCHOR_MAPS.get(lane, {})
    return [
        AuditRow(
            source=lane,
            key=element.key,
            label=element.label,
            clause=element.clause,
            # An element counts as anchored only when the anchor map names it
            # *and* agrees with the encoded clause. A map entry that has drifted
            # from the element is not a confirmation of anything.
            provenance=(
                Provenance.ANCHORED
                if anchored.get(element.key) == element.clause
                else Provenance.PROVISIONAL
            ),
        )
        for element in get_catalogue(lane).elements
    ]


def _correlation_rows() -> list[AuditRow]:
    """Correlation rules cite s.8.4.1.2, s.9.3(6) and s.8.5.1 — sections about
    the *presence* of a declaration rather than a field inside one.

    All three are anchored: the specification names these section numbers in
    prose rather than leaving them to be counted off a table, which is what made
    the lane ordinals provisional in the first place.
    """
    return [
        AuditRow(
            source="correlation",
            key=rule.key,
            label=rule.label,
            clause=rule.clause,
            provenance=Provenance.ANCHORED,
        )
        for rule in RULES
    ]


def _roadmap_rows() -> list[AuditRow]:
    return [
        AuditRow(
            source="roadmap",
            key=activity.key,
            label=activity.label,
            clause=activity.clause,
            provenance=(
                Provenance.ANCHORED
                if activity.clause in ROADMAP_ANCHORED
                else Provenance.PROVISIONAL
            ),
        )
        for activity in ACTIVITIES
    ]


def worksheet() -> list[AuditRow]:
    """Every clause reference this product can put in front of a client.

    Nothing is filtered. A row that does not appear here is a clause nobody
    audits, which is the condition this instrument exists to make impossible.
    """
    rows: list[AuditRow] = []
    for lane in ALL_LANES:
        rows.extend(_lane_rows(lane))
    rows.extend(_correlation_rows())
    rows.extend(_roadmap_rows())
    return rows


def coverage() -> dict[str, dict[str, Any]]:
    """Per-source confirmation counts. The honest headline of the audit."""
    summary: dict[str, dict[str, Any]] = {}
    for row in worksheet():
        entry = summary.setdefault(
            row.source, {"total": 0, "anchored": 0, "provisional": 0, "unconfirmed": []}
        )
        entry["total"] += 1
        if row.confirmed:
            entry["anchored"] += 1
        else:
            entry["provisional"] += 1
            entry["unconfirmed"].append(row.clause)
    for entry in summary.values():
        entry["percent_confirmed"] = round(100 * entry["anchored"] / entry["total"], 2)
    return summary


def duplicated_clauses() -> dict[str, list[str]]:
    """Clauses cited by more than one element within the same source.

    Two elements claiming one ordinal means at least one of them is wrong, and it
    is the single most likely transcription error when a table is keyed in by
    hand. Across sources is fine and expected — a correlation rule and a field
    check may both cite s.9.3(6).
    """
    seen: dict[tuple[str, str], list[str]] = {}
    for row in worksheet():
        seen.setdefault((row.source, row.clause), []).append(row.key)
    return {
        f"{source}:{clause}": keys
        for (source, clause), keys in seen.items()
        if len(keys) > 1
    }


def stale_anchors() -> dict[str, dict[str, str]]:
    """Anchor-map entries that no longer match the catalogue.

    An anchor is a claim that a human confirmed *this key* carries *this clause*.
    Edit the element's clause afterwards and the claim silently transfers to the
    new number, which is the worst kind of wrong: an unconfirmed ordinal wearing
    a confirmed label. This finds those, and it also finds anchors naming a key
    that no longer exists.
    """
    stale: dict[str, dict[str, str]] = {}
    for lane, anchors in ANCHOR_MAPS.items():
        elements = {
            element.key: element.clause
            for element in get_catalogue(cast(Lane, lane)).elements
        }
        for key, clause in anchors.items():
            if key not in elements:
                stale[f"{lane}.{key}"] = {"anchored_as": clause, "actual": "element removed"}
            elif elements[key] != clause:
                stale[f"{lane}.{key}"] = {"anchored_as": clause, "actual": elements[key]}
    return stale


def ordering_findings() -> dict[str, str]:
    """References declared out of the order the guideline states them.

    Encoded tables are keyed in from the document top to bottom, so a reference
    that arrives out of sequence is usually a row inserted in the wrong place —
    and the reader who checks the report against the PDF will find it before we
    do. Notations are sequenced separately: a lane holding both an ordinal table
    and a section reference is not disordered merely for holding both.

    ``tests/test_catalogue.py`` previously checked this for SBOM and AIBOM only,
    because the other three lanes use a notation the check did not understand.
    Three of five lanes therefore had no ordering check at all.

    Applied to the five lane tables and to nothing else. The correlation rules
    and the roadmap activities are curated lists drawing on scattered sections —
    7.1.6 beside 2.3 beside 3.3.3.1 — ordered by lifecycle phase because that is
    how they are read. Sequencing them by ordinal would report a finding on every
    one and mean nothing.
    """
    findings: dict[str, str] = {}
    by_source: dict[tuple[str, Notation], list[AuditRow]] = {}
    for row in worksheet():
        if row.source not in ALL_LANES:
            continue
        by_source.setdefault((row.source, notation_of(row.clause)), []).append(row)

    for (source, notation), rows in by_source.items():
        keys = [_sort_key(row.clause) for row in rows]
        for index in range(1, len(keys)):
            if keys[index] < keys[index - 1]:
                findings[f"{source}.{rows[index].key}"] = (
                    f"{rows[index].clause} is declared after {rows[index - 1].clause}"
                )
        if notation is Notation.TABLE_ORDINAL:
            ordinals = [key[-1] for key in keys]
            if sorted(ordinals) != list(range(1, len(ordinals) + 1)):
                findings[f"{source}:ordinals"] = (
                    f"table ordinals are not 1..{len(ordinals)} without a gap: {ordinals}"
                )
    return findings


def near_collisions() -> dict[str, list[str]]:
    """References within one source that differ only in notation.

    ``10.2(4)`` and ``10.2.4`` are distinct clauses of the guideline and are
    indistinguishable at a glance in a rendered report. A client reading one and
    checking the other against the PDF concludes the assessment cites the wrong
    section, and they cannot be talked out of it — the two strings really do look
    like a typo for each other.

    The fix is never to renumber the guideline. It is to render section
    references with the ``s.`` prefix the product already uses in prose, so the
    two are distinguishable on the page.
    """
    grouped: dict[tuple[str, tuple[int, ...]], set[str]] = {}
    for row in worksheet():
        grouped.setdefault((row.source, _sort_key(row.clause)), set()).add(row.clause)
    return {
        source: sorted(clauses)
        for (source, _), clauses in grouped.items()
        if len(clauses) > 1
    }


def cite(clause: str) -> str:
    """The unambiguous rendering of a clause reference.

    A section reference carries the ``s.`` prefix; a table ordinal does not need
    one because its parentheses already mark it. See `near_collisions`.

    Anything that is not a clause reference is returned untouched. Renderers call
    this on whatever the field result carried, and a missing clause must come out
    as it went in rather than as ``s.None``.
    """
    if not clause or not any(character.isdigit() for character in clause):
        return clause
    return f"s.{clause}" if notation_of(clause) is Notation.SECTION else clause


def render_markdown() -> str:
    """The worksheet an assessor works through, clause by clause.

    Published rather than kept internal, for the reason §11 gives: this
    repository ships what it asks of suppliers, and a supplier who told us "our
    figures are partly unverified" would be doing precisely this.
    """
    summary = coverage()
    total = sum(entry["total"] for entry in summary.values())
    anchored = sum(entry["anchored"] for entry in summary.values())
    percent = round(100 * anchored / total, 2) if total else 0.0

    lines = [
        "# Catalogue audit worksheet",
        "",
        "Every clause reference this product can place in front of a client, with "
        "its provenance. **Anchored** means the ordinal has been confirmed against "
        "the published CERT-In guideline v2.0 (09.07.2025). **Provisional** means "
        "it was encoded from the table and has not been.",
        "",
        f"**{anchored} of {total} clause references confirmed ({percent}%).** "
        "The remainder are provisional. That number is published rather than "
        "rounded up, because a provisional ordinal presented as confirmed is the "
        "one defect that would discredit every assessment issued.",
        "",
        "| Source | Confirmed | Total | % |",
        "| --- | ---: | ---: | ---: |",
    ]
    for source in sorted(summary):
        entry = summary[source]
        lines.append(
            f"| {source} | {entry['anchored']} | {entry['total']} | "
            f"{entry['percent_confirmed']}% |"
        )

    lines += ["", "## Rows awaiting confirmation", "",
              "| Source | Key | Element | Clause |", "| --- | --- | --- | --- |"]
    for row in worksheet():
        if not row.confirmed:
            lines.append(f"| {row.source} | {row.key} | {row.label} | {cite(row.clause)} |")

    stale = stale_anchors()
    duplicates = duplicated_clauses()
    ordering = ordering_findings()
    collisions = near_collisions()
    lines += ["", "## Instrument findings", ""]
    for key, detail in ordering.items():
        lines.append(f"- **out of order** `{key}`: {detail}")
    for source, clauses in collisions.items():
        lines.append(
            f"- **near collision** in {source}: {' and '.join(cite(c) for c in clauses)} "
            "differ only in notation"
        )
    if not stale and not duplicates and not ordering and not collisions:
        lines.append(
            "No stale anchors and no duplicated ordinals within a source. These are "
            "mechanical checks only — they do not substitute for the re-derivation."
        )
    else:
        for key, columns in stale.items():
            lines.append(
                f"- **stale anchor** `{key}`: anchored as {columns['anchored_as']}, "
                f"catalogue now says {columns['actual']}"
            )
        for key, element_keys in duplicates.items():
            lines.append(f"- **duplicate ordinal** `{key}` cited by {', '.join(element_keys)}")

    lines += [
        "",
        "## What this document is not",
        "",
        "It is not the audit. Re-deriving a clause from the published guideline is "
        "a person reading a PDF, and no instrument can do it. Anything here that "
        "claimed otherwise would be manufacturing the assurance it is meant to "
        "measure.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    """Write the worksheet to ``dist/catalogue-audit.md`` and print the headline.

    Published for the reason §11 gives: this repository ships what it asks of
    suppliers, and a supplier telling us "26 of our 101 clause references are
    confirmed, here are the other 75" would be doing exactly this.
    """
    from pathlib import Path

    summary = coverage()
    total = sum(entry["total"] for entry in summary.values())
    anchored = sum(entry["anchored"] for entry in summary.values())

    print("\n  catalogue audit — CERT-In guideline v2.0 (09.07.2025)\n")
    for source in sorted(summary):
        entry = summary[source]
        print(
            f"    {source:<12} {entry['anchored']:>3}/{entry['total']:<3} confirmed "
            f"({entry['percent_confirmed']}%)"
        )
    print(f"\n    {anchored} of {total} clause references confirmed "
          f"({round(100 * anchored / total, 2)}%)")

    findings: dict[str, str] = {
        **ordering_findings(),
        **{key: str(columns) for key, columns in stale_anchors().items()},
    }
    collisions = near_collisions()
    print("\n  instrument findings:")
    if not findings and not collisions:
        print("    none — mechanical checks only; they do not substitute for the "
              "re-derivation")
    for key, detail in findings.items():
        print(f"    {key}: {detail}")
    for source, clauses in collisions.items():
        print(f"    {source}: {' and '.join(cite(c) for c in clauses)} differ only in notation")

    destination = Path(__file__).resolve().parents[4] / "dist" / "catalogue-audit.md"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_markdown())
    print(f"\n  written to {destination.name}\n")
    return 0


if __name__ == "__main__":  # pragma: no cover - console entry point
    raise SystemExit(main())
