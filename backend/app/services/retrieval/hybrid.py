"""Reciprocal rank fusion. **Why hybrid, and why fused by rank rather than score.**

Vector search and lexical search fail in opposite directions, and each failure is
the other's easy case.

*Vector alone* misses exact tokens. A query naming `tomcat-catalina` or a specific
supplier returns semantically adjacent passages about "application servers" and
never the paragraph that names the thing — because the embedder was never trained
to treat a rare literal as significant.

*Lexical alone* misses paraphrase. House wording that says "the declaration omits
attribution" does not share a term with a query about "missing supplier names",
and term overlap scores it zero.

Fusing them by **rank** rather than by score is the part worth being careful
about. Cosine similarity lives in [-1, 1] and clusters near 0.2–0.4 for related
prose; term overlap is a fraction in [0, 1] and is frequently exactly 1.0. Adding
or averaging those two numbers does not combine two opinions — it lets the
lexical scale dominate whenever it saturates, which is often. Reciprocal rank
fusion only reads *position*, so the two retrievers get an equal vote regardless
of how their scores happen to be distributed.

    RRF(d) = Σ 1 / (k + rank(d))

`k` damps the top of each list: without it the first result of either retriever
is worth more than the next four combined, and a single confident-but-wrong
lexical hit wins outright. 60 is the value from the original TREC work and the
tests assert the behaviour it produces rather than the constant itself.
"""

from __future__ import annotations

from dataclasses import replace

from app.repositories.corpusRepository import ScoredChunk

#: Rank damping. See the module docstring.
RRF_K = 60


def fuse(*rankings: list[ScoredChunk], k: int = RRF_K, limit: int = 8) -> list[ScoredChunk]:
    """Combine ranked lists into one, by position.

    A chunk found by both retrievers accumulates both reciprocals and rises above
    one found emphatically by a single retriever — which is the whole reason to
    run two. `found_by` records which ones, because a reviewer checking a draft
    wants to know whether a passage was agreed on or merely confident.
    """
    fused: dict[str, float] = {}
    best: dict[str, ScoredChunk] = {}
    finders: dict[str, list[str]] = {}

    for ranking in rankings:
        for position, item in enumerate(ranking, start=1):
            key = str(item.chunk_id)
            fused[key] = fused.get(key, 0.0) + 1.0 / (k + position)
            finders.setdefault(key, []).extend(item.found_by)
            # Keep the first-seen payload; the content is identical either way,
            # only the per-retriever score differs and that is being replaced.
            best.setdefault(key, item)

    ordered = sorted(fused.items(), key=lambda pair: pair[1], reverse=True)
    return [
        replace(
            best[key],
            score=round(score, 6),
            found_by=tuple(sorted(set(finders[key]))),
        )
        for key, score in ordered[:limit]
    ]
