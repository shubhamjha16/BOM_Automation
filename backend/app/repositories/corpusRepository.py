"""The corpus. **Every read here is org-scoped, and that is the whole point.**

This repository is the one place in the product where a missing predicate leaks
one client's material into another client's report rather than merely returning
an error. Every other table answers questions about a single engagement; this one
exists to surface passages written for *other* engagements, and only the org scope
distinguishes "another engagement of ours" from "a competitor's".

So there is no method that takes a query without a scope, `scoped()` is inherited
rather than reimplemented, and `tests/test_retrieval.py` seeds the other tenant's
corpus with the *best possible match* for the query — a leak would be the first
result, not a tail case somebody has to go looking for.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy import select

from app.models.corpus import CorpusChunk, CorpusDocument
from app.repositories.base import TenantScopedRepository
from app.services.retrieval.embedding import Embedder, assert_comparable, cosine


@dataclass(frozen=True, slots=True)
class ScoredChunk:
    chunk_id: uuid.UUID
    document_id: uuid.UUID
    title: str
    kind: str
    source_ref: str | None
    content: str
    score: float
    #: Which retriever found it, for the fusion report. A passage found by both
    #: is stronger evidence than one found by either alone, and a reviewer
    #: checking a draft wants to see that.
    found_by: tuple[str, ...]


class CorpusRepository(TenantScopedRepository[CorpusChunk]):
    model = CorpusChunk

    async def add_document(
        self,
        *,
        kind: str,
        title: str,
        chunks: list[tuple[str, str, int]],
        embedder: Embedder,
        source_ref: str | None = None,
        engagement_id: uuid.UUID | None = None,
        meta: dict | None = None,
    ) -> CorpusDocument:
        """Store a document and its already-masked chunks.

        `chunks` carries `(masked_text, lowered, masked_count)` — masking happens
        in `services/retrieval/ingest.py` before this is called, so no unmasked
        prose is ever handed to a writer. The repository does not mask, because a
        repository that silently repairs its input hides the caller that skipped
        the guard.
        """
        document = CorpusDocument(
            org_id=self.org_id,
            kind=kind,
            title=title,
            source_ref=source_ref,
            engagement_id=engagement_id,
            meta=meta,
        )
        self.session.add(document)
        await self.session.flush()

        for ord_, (content, lowered, masked_count) in enumerate(chunks):
            self.session.add(
                CorpusChunk(
                    org_id=self.org_id,
                    document_id=document.id,
                    ord=ord_,
                    content=content,
                    content_lower=lowered,
                    embedding=embedder.embed(content),
                    embedding_model=embedder.model,
                    embedding_dim=embedder.dim,
                    masked_count=masked_count,
                )
            )
        await self.session.flush()
        return document

    async def candidates(
        self, *, kinds: tuple[str, ...] | None = None, exclude_engagement: uuid.UUID | None = None
    ) -> list[tuple[CorpusChunk, CorpusDocument]]:
        """Every chunk this tenant may see, with its document.

        **The single fetch point for search.** Both retrievers rank what this
        returns, so the org predicate is applied once and cannot be forgotten by
        one of them — which is the failure a second query path would eventually
        produce.

        Ranking runs in Python over these rows. On Postgres the embedding column
        is a real `vector(384)` and an `ivfflat` index would let the database do
        the nearest-neighbour work instead; that pushdown is a stated follow-up,
        not something this claims to do today. Exact search is *correct* at every
        corpus size and only slow at large ones, and correctness is what the org
        boundary depends on.
        """
        query = (
            select(CorpusChunk, CorpusDocument)
            .join(CorpusDocument, CorpusChunk.document_id == CorpusDocument.id)
            # Belt and braces: both tables carry org_id and both are constrained.
            # The chunk predicate is the one that matters — it is why org_id is
            # denormalised onto the chunk — and the document predicate means a
            # join that is ever loosened still cannot cross the boundary.
            .where(CorpusChunk.org_id == self.org_id)
            .where(CorpusDocument.org_id == self.org_id)
        )
        if kinds:
            query = query.where(CorpusDocument.kind.in_(kinds))
        if exclude_engagement is not None:
            # Drafting an engagement's report from its own previous report is
            # circular: last quarter's wording is restated as this quarter's
            # finding. Excluded by default at the service layer.
            query = query.where(
                (CorpusDocument.engagement_id.is_(None))
                | (CorpusDocument.engagement_id != exclude_engagement)
            )
        result = await self.session.execute(query)
        return [(chunk, document) for chunk, document in result.all()]

    async def vector_ranked(
        self,
        query_text: str,
        *,
        embedder: Embedder,
        limit: int = 20,
        kinds: tuple[str, ...] | None = None,
        exclude_engagement: uuid.UUID | None = None,
    ) -> list[ScoredChunk]:
        """Cosine similarity over the tenant's chunks."""
        query_vector = embedder.embed(query_text)
        scored: list[ScoredChunk] = []
        for chunk, document in await self.candidates(
            kinds=kinds, exclude_engagement=exclude_engagement
        ):
            if not chunk.embedding:
                continue
            assert_comparable(
                chunk_model=chunk.embedding_model,
                chunk_dim=chunk.embedding_dim,
                embedder=embedder,
            )
            scored.append(
                _scored(chunk, document, cosine(query_vector, list(chunk.embedding)), "vector")
            )
        scored.sort(key=lambda item: item.score, reverse=True)
        return scored[:limit]

    async def lexical_ranked(
        self,
        query_text: str,
        *,
        limit: int = 20,
        kinds: tuple[str, ...] | None = None,
        exclude_engagement: uuid.UUID | None = None,
    ) -> list[ScoredChunk]:
        """Term-overlap ranking — the half that catches exact names.

        Scored as the fraction of distinct query terms present, so a chunk that
        mentions two of three query terms outranks one that repeats a single term
        ten times. Term *frequency* is the wrong signal here: the corpus is house
        prose, and a paragraph that says "licence" repeatedly is not more about
        licences than one that says it once alongside "supplier" and "clause".
        """
        terms = {term for term in _terms(query_text) if len(term) > 2}
        if not terms:
            return []

        scored: list[ScoredChunk] = []
        for chunk, document in await self.candidates(
            kinds=kinds, exclude_engagement=exclude_engagement
        ):
            haystack = set(_terms(chunk.content_lower))
            hits = terms & haystack
            if not hits:
                continue
            scored.append(
                _scored(chunk, document, len(hits) / len(terms), "lexical")
            )
        scored.sort(key=lambda item: item.score, reverse=True)
        return scored[:limit]


def _terms(text: str) -> list[str]:
    import re

    return re.findall(r"[a-z0-9]+", text.lower())


def _scored(
    chunk: CorpusChunk, document: CorpusDocument, score: float, found_by: str
) -> ScoredChunk:
    return ScoredChunk(
        chunk_id=chunk.id,
        document_id=document.id,
        title=document.title,
        kind=document.kind,
        source_ref=document.source_ref,
        content=chunk.content,
        score=score,
        found_by=(found_by,),
    )
