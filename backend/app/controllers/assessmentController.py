"""Assessment rendering and export.

Builds sections from persisted lane results, so an export reflects what was
scored rather than re-running the engine — a re-run could produce a different
number if a feed moved, and an assessment must be reproducible from its record.
"""

from __future__ import annotations

import uuid
from typing import Any

from app.services.render.exporters import docx, json_export, pdf, xlsx
from app.services.render.sections.builder import AssessmentInput, build_sections
from app.services.reviewGate import watermark_for


class _StoredLane:
    """Adapts a persisted lane_result row to what the section builder reads."""

    def __init__(self, row: Any, fields: list[dict[str, Any]]) -> None:
        self.lane = row.lane
        self.verdict = str(row.verdict)
        self.score = float(row.score) if row.score is not None else None
        self.entity_count = row.entity_count
        self.detail = row.detail or ""
        self.field_results = fields


async def _load(lanes: Any, submission_id: uuid.UUID) -> tuple[list[_StoredLane], list[Any]]:
    results = await lanes.for_submission(submission_id)
    stored: list[_StoredLane] = []
    for row in results:
        verdicts = await lanes.verdicts_for(row.id)
        stored.append(
            _StoredLane(
                row,
                [
                    {
                        "element_key": verdict.element_key,
                        "label": verdict.element_key.replace("_", " ").title(),
                        "clause": verdict.clause,
                        "verdict": str(verdict.verdict),
                        "tier": "critical",
                        "populated": verdict.populated,
                        "total": verdict.total,
                        "coverage": float(verdict.coverage)
                        if verdict.coverage is not None
                        else None,
                        "detail": verdict.detail,
                        "consumer_action": verdict.consumer_action,
                    }
                    for verdict in verdicts
                ],
            )
        )
    return stored, await lanes.findings_for(submission_id)


async def render(
    lanes: Any, submission_id: uuid.UUID, *, status: str = "draft"
) -> dict[str, Any]:
    """The assessment as structured sections, with its provenance."""
    stored, findings = await _load(lanes, submission_id)
    scores = [lane.score for lane in stored if lane.score is not None]
    overall = round(sum(scores) / len(scores), 2) if scores else None

    sections = build_sections(
        AssessmentInput(
            submission_id=str(submission_id),
            overall_score=overall,
            lane_results=stored,
            correlation_findings=findings,
        )
    )
    return {
        "submission_id": str(submission_id),
        "overall_score": overall,
        "status": status,
        "watermark": watermark_for(status),
        "sections": [section.as_row() for section in sections],
    }


async def export(
    lanes: Any, submission_id: uuid.UUID, *, fmt: str, status: str = "draft"
) -> tuple[bytes, str, str]:
    """Return (bytes, media type, filename) for a format."""
    stored, findings = await _load(lanes, submission_id)
    scores = [lane.score for lane in stored if lane.score is not None]
    overall = round(sum(scores) / len(scores), 2) if scores else None
    watermark = watermark_for(status)

    sections = build_sections(
        AssessmentInput(
            submission_id=str(submission_id),
            overall_score=overall,
            lane_results=stored,
            correlation_findings=findings,
        )
    )
    stem = f"assessment-{submission_id}"

    if fmt == "xlsx":
        return (
            xlsx.build_gap_register(stored, watermark=watermark),
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            f"gap-register-{submission_id}.xlsx",
        )
    if fmt == "docx":
        return (
            docx.build_assessment(
                sections, title="Conformance assessment", watermark=watermark
            ),
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            f"{stem}.docx",
        )
    if fmt == "pdf":
        # Raises PdfUnavailable where LibreOffice is absent; the router maps it
        # to a 501 naming the formats that do work.
        document = docx.build_assessment(
            sections, title="Conformance assessment", watermark=watermark
        )
        return pdf.from_docx(document), "application/pdf", f"{stem}.pdf"

    return (
        json_export.build_assessment(
            sections,
            submission_id=str(submission_id),
            overall_score=overall,
            lane_results=stored,
            correlation_findings=findings,
            watermark=watermark,
        ),
        "application/json",
        f"{stem}.json",
    )
