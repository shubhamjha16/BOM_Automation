"""Getting prose into the corpus — masked, chunked, embedded, in that order.

**Masking happens here, before anything is written.** Not at query time and not
in the repository. A fact that never enters the corpus cannot be retrieved out of
it by a future code path that forgets to mask, cannot be reached by an injection
that manipulates a query, and cannot survive a database dump into somewhere less
careful. The corpus stores wording; the engine owns facts (§11).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from app.repositories.corpusRepository import CorpusRepository
from app.services.retrieval.chunking import split
from app.services.retrieval.embedding import Embedder, default_embedder
from app.services.retrieval.factGuard import assert_masked, mask_facts


@dataclass(frozen=True, slots=True)
class IngestReport:
    document_id: uuid.UUID
    chunks: int
    masked_facts: int

    def as_row(self) -> dict[str, object]:
        return {
            "document_id": str(self.document_id),
            "chunks": self.chunks,
            "masked_facts": self.masked_facts,
        }


async def ingest(
    repository: CorpusRepository,
    *,
    kind: str,
    title: str,
    text: str,
    source_ref: str | None = None,
    engagement_id: uuid.UUID | None = None,
    embedder: Embedder = default_embedder,
) -> IngestReport:
    """Mask, split, embed and store one document."""
    prepared: list[tuple[str, str, int]] = []
    total_masked = 0

    for chunk in split(text):
        result = mask_facts(chunk)
        # Verified rather than trusted. `mask_facts` and `assert_masked` read the
        # same pattern table, so this catches a pattern that stops matching after
        # an edit — the failure that would otherwise put a live figure in the
        # corpus and be invisible until a client recognised their own number.
        assert_masked(result.text, where=f"corpus ingest of {title!r}")
        prepared.append((result.text, result.text.lower(), result.masked))
        total_masked += result.masked

    document = await repository.add_document(
        kind=kind,
        title=title,
        chunks=prepared,
        embedder=embedder,
        source_ref=source_ref,
        engagement_id=engagement_id,
    )
    return IngestReport(
        document_id=document.id, chunks=len(prepared), masked_facts=total_masked
    )
