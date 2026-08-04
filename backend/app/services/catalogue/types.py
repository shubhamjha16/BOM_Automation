"""The shape of a minimum element.

The catalogue is data, not code constants: S7 seeds these rows into
``minimum_elements`` pinned to a ``guideline_versions`` row with a checksum, and
old assessments keep reporting against the version they were scored under. This
module is the in-process representation both sides share.
"""

from __future__ import annotations

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
