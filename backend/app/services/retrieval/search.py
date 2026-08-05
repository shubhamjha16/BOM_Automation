"""The retrieval half of RAG: query in, fact-masked passages out.

One entry point, `retrieve`, so there is a single place where the org scope, the
embedding-space check, the fusion and the final guard all apply. Two entry points
would mean two places to forget one of them.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from app.repositories.corpusRepository import CorpusRepository, ScoredChunk
from app.services.retrieval.embedding import Embedder, default_embedder
from app.services.retrieval.factGuard import assert_masked
from app.services.retrieval.hybrid import fuse
from app.utils.logger import get_logger

logger = get_logger(__name__)

#: How many passages reach a prompt. Small on purpose: the job is to show a
#: drafter the house voice, and eight paragraphs demonstrate a voice. Forty
#: crowd out the actual findings and invite the model to summarise the corpus
#: instead of the assessment.
DEFAULT_LIMIT = 8


@dataclass(frozen=True, slots=True)
class Retrieval:
    query: str
    passages: list[ScoredChunk]
    #: Reported, not hidden. An empty corpus is the normal state for a new firm,
    #: and a drafter given nothing must say so rather than invent house style.
    corpus_empty: bool

    def as_report(self) -> dict[str, object]:
        return {
            "query": self.query,
            "corpus_empty": self.corpus_empty,
            "passages": [
                {
                    "title": passage.title,
                    "kind": passage.kind,
                    "source_ref": passage.source_ref,
                    "score": passage.score,
                    "found_by": list(passage.found_by),
                    "content": passage.content,
                }
                for passage in self.passages
            ],
        }


async def retrieve(
    repository: CorpusRepository,
    query: str,
    *,
    limit: int = DEFAULT_LIMIT,
    kinds: tuple[str, ...] | None = None,
    exclude_engagement: uuid.UUID | None = None,
    embedder: Embedder = default_embedder,
) -> Retrieval:
    """Hybrid search over one tenant's corpus.

    `exclude_engagement` defaults to nothing here and is set by the narrative
    service to the engagement being drafted: reusing an engagement's own previous
    report as the source for its next one restates last quarter's wording as this
    quarter's finding, which reads like progress and is not.
    """
    vector = await repository.vector_ranked(
        query,
        embedder=embedder,
        limit=limit * 3,
        kinds=kinds,
        exclude_engagement=exclude_engagement,
    )
    lexical = await repository.lexical_ranked(
        query, limit=limit * 3, kinds=kinds, exclude_engagement=exclude_engagement
    )

    if not vector and not lexical:
        candidates = await repository.candidates(
            kinds=kinds, exclude_engagement=exclude_engagement
        )
        logger.info("retrieval_empty", query_terms=len(query.split()), corpus=len(candidates))
        return Retrieval(query=query, passages=[], corpus_empty=not candidates)

    passages = fuse(vector, lexical, limit=limit)

    # The final gate before any of this can reach a prompt. Chunks were masked at
    # ingest, so this should never fire — which is exactly why it is worth having:
    # if it ever does, a write path bypassed the guard and the corpus is polluted.
    for passage in passages:
        assert_masked(passage.content, where=f"retrieval for {query!r}")

    logger.info(
        "retrieval_complete",
        vector_hits=len(vector),
        lexical_hits=len(lexical),
        fused=len(passages),
        agreed=sum(1 for passage in passages if len(passage.found_by) > 1),
    )
    return Retrieval(query=query, passages=passages, corpus_empty=False)
