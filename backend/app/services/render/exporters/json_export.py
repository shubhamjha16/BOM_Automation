"""JSON export — the machine-readable assessment.

Carries the provenance chain rather than only the prose, so a consumer's own
tooling can follow a section to the field verdicts behind it without scraping a
document.
"""

from __future__ import annotations

import json
from typing import Any


def build_assessment(
    sections: list[Any],
    *,
    submission_id: str,
    overall_score: float | None,
    lane_results: list[Any],
    correlation_findings: list[Any],
    watermark: str | None = None,
) -> bytes:
    payload: dict[str, Any] = {
        "submission_id": submission_id,
        "overall_score": overall_score,
        "guideline": {
            "ref": "CERT-In Technical Guidelines on SBOM, QBOM & CBOM, AIBOM and HBOM",
            "version": "2.0",
        },
        "disclaimer": (
            "A conformance assessment, not a legal opinion. Consumer determinations "
            "were not assessed."
        ),
        "lanes": [
            {
                "lane": lane.lane,
                "verdict": str(lane.verdict),
                "score": lane.score,
                "entity_count": lane.entity_count,
                "detail": lane.detail,
                "fields": getattr(lane, "field_results", None) or [],
            }
            for lane in lane_results
        ],
        "correlation_findings": [
            {
                "rule_key": finding.rule_key,
                "clause": finding.clause,
                "severity": str(finding.severity),
                "detail": finding.detail,
            }
            for finding in correlation_findings
        ],
        "sections": [section.as_row() for section in sections],
    }
    if watermark:
        payload["watermark"] = watermark

    return (json.dumps(payload, indent=2, default=str) + "\n").encode()
