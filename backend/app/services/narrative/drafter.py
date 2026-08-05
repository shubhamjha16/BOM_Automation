"""RAG, assembled — and the boundary that keeps §11 true across it.

    retrieve (org-scoped, fact-masked)  ->  augment (facts + house wording)
                                        ->  generate  ->  VERIFY  ->  section

The verify step is the one that matters and the reason this module exists rather
than the graph node calling a generator directly.

**A model given facts will still produce facts that were not given.** It rounds
38.21 to 38. It totals two counts into a third. It writes "4.2(4)" when it was
handed "4.2(5)" because they are adjacent in its training. Each of those is a
figure with no provenance in a document whose entire value is that every figure
has one. The conformance gate downstream checks that a clause *resolves* — and a
fabricated 4.2(4) resolves perfectly, because it is a real clause. Resolution is
not the property we need here. **Provenance is.**

So every figure and clause in the generated text is checked against the facts
that were supplied, and an unsupported one is a refusal rather than a warning.
Warnings get shipped.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from app.repositories.corpusRepository import CorpusRepository
from app.services.graph.prompts.sectionDrafter import build as build_prompt
from app.services.narrative.generator import Generator, default_generator
from app.services.retrieval.factGuard import _PATTERNS
from app.services.retrieval.search import Retrieval, retrieve
from app.utils.logger import get_logger

logger = get_logger(__name__)

#: Fact types the generated text is checked for. Deliberately not `count`: prose
#: legitimately contains "three lanes" and "one supplier", and a rule that
#: refused every digit would refuse every draft. Percentages, clauses, CVE ids
#: and dates are the ones that carry a claim about *this* assessment.
_CHECKED = ("percent", "clause", "cve", "date")


class UnsupportedFigure(RuntimeError):
    """The draft asserted a figure or clause that was never supplied to it."""


@dataclass(frozen=True, slots=True)
class DraftedSection:
    section: str
    content: str
    generator: str
    #: Empty when no provider is configured. Reported so a reader knows whether
    #: they are looking at drafted prose or the engine's own restatement.
    drafted: bool
    retrieval: Retrieval | None = None
    supplied_facts: list[str] = field(default_factory=list)

    def as_row(self) -> dict[str, object]:
        return {
            "section": self.section,
            "content": self.content,
            "generator": self.generator,
            "drafted": self.drafted,
            "house_passages": len(self.retrieval.passages) if self.retrieval else 0,
            "supplied_facts": list(self.supplied_facts),
        }


def _figures(text: str) -> set[str]:
    """Every checked fact token appearing in a piece of text."""
    found: set[str] = set()
    for name, pattern, _placeholder in _PATTERNS:
        if name in _CHECKED:
            found.update(match.strip() for match in pattern.findall(text))
    return found


def verify(draft: str, *, facts: str, section: str) -> None:
    """Refuse a draft asserting anything it was not given.

    Normalised on both sides before comparison so `s.4.2(5)` in the facts covers
    `4.2(5)` in the draft — the model dropping a prefix is a formatting choice,
    not a fabrication, and refusing it would train everyone to disable the check.
    """
    supplied = {_normalise(item) for item in _figures(facts)}
    unsupported = sorted(
        item for item in _figures(draft) if _normalise(item) not in supplied
    )
    if unsupported:
        raise UnsupportedFigure(
            f"{section}: the draft asserts {unsupported} which was not supplied in "
            "FACTS. Every figure and clause in an assessment traces to a field "
            "verdict; one that does not has no provenance and cannot be issued (§11)."
        )


def _normalise(token: str) -> str:
    return (
        token.lower()
        .removeprefix("s.")
        .removeprefix("rec.")
        .removeprefix("clause")
        .strip()
        .replace(" ", "")
    )


async def draft_section(
    repository: CorpusRepository,
    *,
    section: str,
    facts: str,
    query: str | None = None,
    engagement_id: uuid.UUID | None = None,
    generator: Generator = default_generator,
    max_words: int = 220,
) -> DraftedSection:
    """Retrieve house wording, draft the section, and verify what comes back."""
    retrieval = await retrieve(
        repository,
        query or section,
        # An engagement's own prior report is excluded: drafting this quarter's
        # findings from last quarter's wording restates the old text as new, which
        # reads as continuity and is actually a copy.
        exclude_engagement=engagement_id,
    )
    house_wording = "\n\n".join(passage.content for passage in retrieval.passages)

    system, user = build_prompt(
        section=section, facts=facts, house_wording=house_wording, max_words=max_words
    )
    content = generator.complete(system, user, max_words=max_words)

    if generator.available:
        # Only checked for a real draft. The null generator restates the supplied
        # facts verbatim, so it is trivially supported — running the check over it
        # would test the echo, not the guard.
        verify(content, facts=facts, section=section)

    logger.info(
        "section_drafted",
        section=section,
        generator=generator.name,
        drafted=generator.available,
        house_passages=len(retrieval.passages),
        corpus_empty=retrieval.corpus_empty,
    )
    return DraftedSection(
        section=section,
        content=content,
        generator=generator.name,
        drafted=generator.available,
        retrieval=retrieval,
        supplied_facts=sorted(_figures(facts)),
    )
