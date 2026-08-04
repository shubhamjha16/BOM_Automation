"""Catalogue read model. Routers stay thin; the shaping happens here."""

from __future__ import annotations

from typing import Any

from app.configs.envConfig import Lane
from app.services.catalogue.loader import catalogue_checksum, get_catalogue, guideline_ref


def list_elements(lane: Lane) -> dict[str, Any]:
    catalogue = get_catalogue(lane)
    return {
        "lane": lane,
        "clause_root": catalogue.clause_root,
        "guideline": guideline_ref(),
        "catalogue_checksum": catalogue_checksum(lane),
        "element_count": len(catalogue.elements),
        "supplier_scored_count": len(catalogue.supplier_scored),
        "consumer_determined_count": len(catalogue.consumer_determined),
        "elements": [
            {
                "key": element.key,
                "label": element.label,
                "clause": element.clause,
                "tier": str(element.tier),
                "determinability": str(element.determinability),
                "scope": str(element.scope),
                "scores_against_supplier": element.scores_against_supplier,
                "rationale": element.rationale or None,
                "consumer_action": element.consumer_action or None,
            }
            for element in catalogue.elements
        ],
    }
