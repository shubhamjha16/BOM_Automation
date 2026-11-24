"""The shape of a minimum element.

The catalogue is data, not code constants: S7 seeds these rows into
``minimum_elements`` pinned to a ``guideline_versions`` row with a checksum, and
old assessments keep reporting against the version they were scored under. This
module is the in-process representation both sides share.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from app.configs.envConfig import Lane
from app.configs.jobTypes import Determinability, Tier

#: Reads one normalised entity and answers "is this field populated here?".
#: Pure, total, and never raises — a shape check that throws would turn a
#: malformed supplier value into a crashed lane.
FieldProbe = Callable[[dict[str, Any]], bool]


class Scope(StrEnum):
    """What a minimum element is a property *of*.

    Getting this wrong produces a false negative that is invisible in the
    arithmetic: the SBOM's timestamp and author live on the document, so probing
    for them once per component reports them absent across every entity and tells
    a supplier they failed a clause they actually met. A report wrong against the
    supplier is as damaging as one wrong in their favour.
    """

    #: A property of each component, model, crypto asset or hardware item.
    ENTITY = "entity"
    #: A property of the BOM document itself — scored once per document.
    DOCUMENT = "document"


def table_clause(section: str, table: int, name: str, group: str | None = None) -> str:
    """The citation for an element of one of the guideline's *unnumbered* tables.

    Tables 8 to 11 (QBOM and CBOM, AIBOM, HBOM) list elements by name and give them
    no clause numbers, so the only faithful reference is where the element sits and
    what the guideline calls it: ``"9.3 Table 10: Software Dependencies"``. A table
    that groups its rows (Table 9's Algorithms, Keys, Protocols, Certificates;
    Table 11's product and component rows) puts the group before the name, because
    the same name can occur in two groups: ``"8.3 Table 9: Keys - Name"``.
    """
    label = f"{group} - {name}" if group else name
    return f"{section} Table {table}: {label}"


def label_repeats_clause(clause: str, label: str) -> bool:
    """True when a table citation already ends with the element's name.

    ``8.3 Table 9: Keys - Creation Date`` already says "Keys - Creation Date", so a sentence that
    prints the clause and then the label would say it twice. A trailing note on the label, such as
    ``(product)``, is ignored.
    """
    base = re.sub(r"\s*\([^)]*\)\s*$", "", label or "").strip().lower()
    return bool(base) and clause.strip().lower().endswith(base)


def clause_with_label(clause: str, label: str) -> str:
    """The clause and the element's label for a sentence, without repeating a name."""
    return clause if label_repeats_clause(clause, label) else f"{clause} {label}"


@dataclass(frozen=True, slots=True)
class MinimumElement:
    """One row of a CERT-In minimum-element table."""

    key: str
    label: str
    #: Clause in the pinned guideline version. Every rendered verdict resolves
    #: through this to the published document, or the gate blocks it (S8).
    clause: str
    tier: Tier
    determinability: Determinability
    probe: FieldProbe
    #: Whether this is a property of each entity or of the document as a whole.
    scope: Scope = Scope.ENTITY
    #: Why a HUMAN-determinability element cannot come from a BOM artifact, and
    #: what the consumer must do instead. Rendered beside the verdict.
    rationale: str = ""
    consumer_action: str = ""

    def __post_init__(self) -> None:
        if self.determinability is Determinability.HUMAN and not self.consumer_action:
            raise ValueError(
                f"{self.key}: a HUMAN-determinability element must carry the consumer "
                "action required; a not_determinable verdict without one renders as a "
                "shrug, and the reader assumes it passed"
            )

    @property
    def scores_against_supplier(self) -> bool:
        """HUMAN elements are excluded from the supplier score entirely (§11).

        Criticality (4.2(12)) is relative to the consuming deployment and Usage
        Restrictions (4.2(13)) is a legal determination — a supplier could not
        have supplied either. Scoring them as defects produces a report that is
        wrong in the client's favour.
        """
        return self.determinability is not Determinability.HUMAN


@dataclass(frozen=True, slots=True)
class Catalogue:
    """A lane's full minimum-element table for one guideline version."""

    lane: Lane
    #: Section of the guideline this table is drawn from, e.g. "4.2".
    clause_root: str
    guideline_version: str
    elements: Sequence[MinimumElement]

    def __post_init__(self) -> None:
        keys = [element.key for element in self.elements]
        duplicates = {key for key in keys if keys.count(key) > 1}
        if duplicates:
            raise ValueError(f"{self.lane}: duplicate element keys {sorted(duplicates)}")

    def by_key(self, key: str) -> MinimumElement:
        for element in self.elements:
            if element.key == key:
                return element
        raise KeyError(f"{self.lane} catalogue has no element {key!r}")

    @property
    def supplier_scored(self) -> list[MinimumElement]:
        return [element for element in self.elements if element.scores_against_supplier]

    @property
    def entity_scoped(self) -> list[MinimumElement]:
        return [element for element in self.elements if element.scope is Scope.ENTITY]

    @property
    def document_scoped(self) -> list[MinimumElement]:
        return [element for element in self.elements if element.scope is Scope.DOCUMENT]

    @property
    def consumer_determined(self) -> list[MinimumElement]:
        return [element for element in self.elements if not element.scores_against_supplier]
