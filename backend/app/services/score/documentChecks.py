"""Document-scoped minimum elements, scored once per BOM document.

The SBOM's author and timestamp are properties of the document, not of each
component. Probing for them per component reports them absent across every entity
and tells a supplier they failed a clause they demonstrably met — a false
negative that the weighted score hides completely, because 0/855 looks exactly
like a genuine gap.

Coverage here counts documents rather than entities: two documents in a lane, one
carrying a timestamp, is 1/2 and not a pass. The same "partial coverage is not a
pass" rule, applied at the level the field actually lives at.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from app.services.catalogue.types import Catalogue, MinimumElement, Scope
from app.services.score.fieldCheck import FieldResult, check


def document_metadata(
    *, author: str | None, timestamp: str | None, spec_version: str | None = None
) -> dict[str, Any]:
    """The normalised document-level record a document-scoped probe reads.

    Carries both the canonical key and the source-shaped one, as the entity
    normaliser does, so a probe can name either.
    """
    return {
        "author": author,
        "originator": author,
        "doc_author": author,
        "timestamp": timestamp,
        "doc_timestamp": timestamp,
        "spec_version": spec_version,
    }


def check_document(
    element: MinimumElement, documents: Sequence[dict[str, Any]]
) -> FieldResult:
    """Score one document-scoped element across the lane's documents."""
    if element.scope is not Scope.DOCUMENT:
        raise ValueError(
            f"{element.key} is {element.scope}-scoped; use score.fieldCheck.check"
        )
    return check(element, documents)


def check_all(
    catalogue: Catalogue,
    entities: Sequence[dict[str, Any]],
    documents: Sequence[dict[str, Any]],
) -> list[FieldResult]:
    """Score a full catalogue, routing each element to its scope.

    Returns results in catalogue order so the assessment appendix reads in clause
    order regardless of scope.
    """
    return [
        check_document(element, documents)
        if element.scope is Scope.DOCUMENT
        else check(element, entities)
        for element in catalogue.elements
    ]
