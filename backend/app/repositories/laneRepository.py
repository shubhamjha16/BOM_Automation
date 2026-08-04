"""Lane results, field verdicts and rejected entries."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from app.models.bomDocument import BomDocument
from app.models.correlationFinding import CorrelationFindingRow
from app.models.laneResult import FieldVerdictRow, LaneResult
from app.models.rawEntry import RawEntry
from app.repositories.base import TenantScopedRepository


class LaneRepository(TenantScopedRepository[LaneResult]):
    model = LaneResult

    async def record(
        self,
        *,
        submission_id: uuid.UUID,
        lane: str,
        verdict: str,
        score: float | None,
        entity_count: int,
        detail: str,
        engine_version: str,
        inputs_hash: str | None,
        guideline_version_id: uuid.UUID | None,
        field_results: list[dict[str, Any]] | None = None,
        element_ids: dict[str, uuid.UUID] | None = None,
    ) -> LaneResult:
        """Persist one lane result and its field verdicts.

        `guideline_version_id` is the pin: this result reports against the
        catalogue as it was when scored, whatever the encoded one becomes later.
        """
        result = LaneResult(
            org_id=self.org_id,
            submission_id=submission_id,
            guideline_version_id=guideline_version_id,
            lane=lane,
            verdict=verdict,
            score=score,
            entity_count=entity_count,
            detail=detail,
            engine_version=engine_version,
            inputs_hash=inputs_hash,
            computed_at=datetime.now(UTC),
        )
        self.session.add(result)
        await self.session.flush()

        for field in field_results or []:
            self.session.add(
                FieldVerdictRow(
                    org_id=self.org_id,
                    lane_result_id=result.id,
                    minimum_element_id=(element_ids or {}).get(field["element_key"]),
                    element_key=field["element_key"],
                    clause=field["clause"],
                    verdict=field["verdict"],
                    populated=field["populated"],
                    total=field["total"],
                    coverage=field["coverage"],
                    weight=field["weight"],
                    detail=field["detail"],
                    consumer_action=field.get("consumer_action") or None,
                )
            )
        await self.session.flush()
        return result

    async def for_submission(self, submission_id: uuid.UUID) -> list[LaneResult]:
        result = await self.session.execute(
            self.scoped()
            .where(LaneResult.submission_id == submission_id)
            .order_by(LaneResult.lane)
        )
        return list(result.scalars().all())

    async def verdicts_for(self, lane_result_id: uuid.UUID) -> list[FieldVerdictRow]:
        """Backed by `ix_field_verdicts_lane_result_id_verdict`."""
        result = await self.session.execute(
            select(FieldVerdictRow)
            .where(FieldVerdictRow.org_id == self.org_id)
            .where(FieldVerdictRow.lane_result_id == lane_result_id)
            .order_by(FieldVerdictRow.clause)
        )
        return list(result.scalars().all())

    # --- rejected entries (S6) ---------------------------------------------

    async def record_rejections(
        self, *, bom_document_id: uuid.UUID, rejections: list[Any]
    ) -> int:
        for entry in rejections:
            self.session.add(
                RawEntry(
                    org_id=self.org_id,
                    bom_document_id=bom_document_id,
                    ord=entry.ord,
                    parse_status="rejected",
                    reason=entry.reason,
                    ref=entry.ref,
                    payload=entry.payload if isinstance(entry.payload, dict) else None,
                )
            )
        await self.session.flush()
        return len(rejections)

    async def rejected_for_submission(self, submission_id: uuid.UUID) -> list[dict[str, Any]]:
        """Every dropped entry across the submission's documents, with a reason.

        Joined through `bom_documents` so the caller sees which document and lane
        each rejection came from — "entry 47 was dropped" is not actionable
        without knowing which of five files entry 47 is in.
        """
        result = await self.session.execute(
            select(RawEntry, BomDocument)
            .join(BomDocument, RawEntry.bom_document_id == BomDocument.id)
            .where(RawEntry.org_id == self.org_id)
            .where(BomDocument.submission_id == submission_id)
            .order_by(BomDocument.lane, RawEntry.ord)
        )
        return [
            {
                "document_id": str(document.id),
                "lane": document.lane,
                "filename": document.filename,
                "ord": entry.ord,
                "ref": entry.ref,
                "reason": entry.reason,
                "parse_status": entry.parse_status,
            }
            for entry, document in result.all()
        ]

    # --- correlation findings (S9) -----------------------------------------

    async def record_findings(self, *, submission_id: uuid.UUID, findings: list[Any]) -> int:
        for finding in findings:
            self.session.add(
                CorrelationFindingRow(
                    org_id=self.org_id,
                    submission_id=submission_id,
                    rule_key=finding.rule_key,
                    severity=str(finding.severity),
                    clause=finding.clause,
                    detail=finding.detail,
                    left_ref=finding.left_ref,
                    right_ref=finding.right_ref,
                )
            )
        await self.session.flush()
        return len(findings)

    async def findings_for(self, submission_id: uuid.UUID) -> list[CorrelationFindingRow]:
        result = await self.session.execute(
            select(CorrelationFindingRow)
            .where(CorrelationFindingRow.org_id == self.org_id)
            .where(CorrelationFindingRow.submission_id == submission_id)
            .order_by(CorrelationFindingRow.severity, CorrelationFindingRow.rule_key)
        )
        return list(result.scalars().all())
