"""Org-scoped retrieval, and the two guards that make it safe to draft from.

Retrieval over past assessments is the most dangerous component in this product,
and it is worth being precise about why. Everything else holds one client's data
and answers questions about that client. This holds the firm's prose across
*every* client, and its whole purpose is to surface passages from one engagement
while drafting another. Two things must hold, always:

**Tenancy.** The isolation test does not seed an unrelated document in the other
org and check it does not appear — that would pass with no scoping at all if the
ranking happened to prefer the right tenant. It seeds the other org with the
*best possible match* for the query, so a missing predicate surfaces as the
**first** result.

**Facts do not travel.** The corpus stores wording; figures come from the scoring
engine (§11). A drafter shown three retrieved paragraphs will otherwise put one
client's percentage into another client's report, in fluent prose, with nothing
downstream able to catch it — a borrowed "4.2(5)" resolves perfectly against the
guideline.
"""

from __future__ import annotations

import ast
import uuid

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.models import Base, Client, Engagement, Org
from app.repositories.corpusRepository import CorpusRepository
from app.services.narrative.drafter import UnsupportedFigure, draft_section, verify
from app.services.narrative.generator import Generator, NullGenerator
from app.services.retrieval.chunking import MAX_CHUNK_CHARS, split
from app.services.retrieval.embedding import (
    EmbeddingSpaceMismatch,
    HashingEmbedder,
    assert_comparable,
    cosine,
    default_embedder,
)
from app.services.retrieval.factGuard import (
    UnmaskedFact,
    assert_masked,
    mask_facts,
    residual_facts,
)
from app.services.retrieval.hybrid import fuse
from app.services.retrieval.ingest import ingest
from app.services.retrieval.search import retrieve

# --- fact masking: the corpus stores wording, never figures ------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("failing 4.2(5).", "failing ⟨clause⟩."),
        ("scored 38.28%", "scored ⟨percent⟩"),
        ("s.8.4.1.2 applies", "⟨clause⟩ applies"),
        ("CVE-2021-44228 is listed", "⟨cve⟩ is listed"),
        ("as of 2025-07-09", "as of ⟨date⟩"),
        ("log4j-core@2.14.1", "log4j-core⟨version⟩"),
        ("named under 5.1(d)", "named under ⟨clause⟩"),
        ("absent across 388 of 412", "absent across ⟨count⟩ of ⟨count⟩"),
    ],
)
def test_every_fact_shape_is_masked(text, expected):
    assert mask_facts(text).text == expected


def test_the_pattern_order_is_the_correctness_argument():
    """Each of these was wrong on the first attempt, and each failed *silently* —
    the text was still masked, just as the wrong type, and nothing downstream
    could tell."""
    # percent before clause, or 38.28% becomes ⟨clause⟩%
    assert mask_facts("38.28%").text == "⟨percent⟩"
    # clause before count, or 4.2(5) becomes ⟨clause⟩(⟨count⟩)
    assert mask_facts("4.2(5)").text == "⟨clause⟩"
    # version before clause, or v3.0.0 becomes ⟨version⟩.⟨clause⟩
    assert mask_facts("v3.0.0").text == "⟨version⟩"
    # cve first, or the year is eaten as a date and the tail as a count
    assert mask_facts("CVE-2021-44228").text == "⟨cve⟩"


def test_masked_text_carries_no_residual_facts():
    prose = (
        "The supplier scored 38.28% over 855 components as of 2025-07-09, failing "
        "s.4.2(5) and 4.2(21), with CVE-2021-44228 unaddressed in log4j-core@2.14.1."
    )
    result = mask_facts(prose)
    assert result.masked >= 7
    assert residual_facts(result.text) == []


def test_prose_with_no_facts_is_left_alone():
    """A house-style paragraph legitimately carries none, and masking is not
    supposed to damage the wording that is the entire point of retrieving it."""
    prose = "We recommend the supplier restate their declaration before resubmission."
    result = mask_facts(prose)
    assert result.text == prose
    assert result.is_clean


def test_assert_masked_raises_rather_than_masking_late():
    """A late mask would hide the path that skipped the guard, and that path
    would still be there tomorrow with a different caller."""
    with pytest.raises(UnmaskedFact, match="another engagement"):
        assert_masked("the supplier scored 38.28%", where="test")


# --- embeddings ---------------------------------------------------------------


def test_embeddings_are_deterministic_across_calls():
    """Retrieval ranking is only assertable in a test because of this."""
    assert default_embedder.embed("licence coverage") == default_embedder.embed(
        "licence coverage"
    )


def test_embeddings_are_unit_length():
    vector = default_embedder.embed("post-quantum migration strategy")
    assert abs(sum(value * value for value in vector) - 1.0) < 1e-9


def test_related_prose_scores_above_unrelated_prose():
    """The embedder is not a toy — it has to actually discriminate, or hybrid
    search is lexical search with extra steps."""
    query = default_embedder.embed("licence declarations are missing for components")
    related = default_embedder.embed("licences are absent across most of the components")
    unrelated = default_embedder.embed("the asset register lists serial numbers and warranty")

    assert cosine(query, related) > cosine(query, unrelated) * 2


def test_ranking_across_two_embedding_spaces_is_refused():
    """The failure that produces no error: change the embedder, leave the old
    vectors, and every similarity is a real number over two unrelated coordinate
    systems. The ranking looks fine. It is noise."""
    with pytest.raises(EmbeddingSpaceMismatch, match="re-embed"):
        assert_comparable(
            chunk_model="some-other-model", chunk_dim=384, embedder=default_embedder
        )
    with pytest.raises(EmbeddingSpaceMismatch, match="re-embed"):
        assert_comparable(chunk_model="hashing-ngram-v1", chunk_dim=768, embedder=default_embedder)


def test_a_chunk_with_no_provenance_is_refused_rather_than_assumed():
    with pytest.raises(EmbeddingSpaceMismatch, match="re-embedded"):
        assert_comparable(chunk_model=None, chunk_dim=None, embedder=default_embedder)


def test_comparing_different_widths_raises_rather_than_truncating():
    with pytest.raises(ValueError, match="dimensional"):
        cosine([0.1] * 8, [0.1] * 16)


def test_a_narrower_embedder_is_a_different_space():
    narrow = HashingEmbedder(dim=64, model="hashing-ngram-v1")
    assert len(narrow.embed("anything")) == 64
    with pytest.raises(EmbeddingSpaceMismatch):
        assert_comparable(chunk_model=narrow.model, chunk_dim=narrow.dim, embedder=default_embedder)


# --- chunking -----------------------------------------------------------------


def test_a_heading_is_carried_forward_onto_its_section():
    """A heading names its section. Attaching it backwards files it under the
    wrong subject; dropping it loses the only word saying what the passage is
    about — and dropping it is what the first implementation did."""
    chunks = split("Licence coverage\n\n" + "Licences were absent across the estate. " * 3)
    assert chunks
    assert chunks[0].startswith("Licence coverage —")


def test_a_long_paragraph_is_split_on_sentence_boundaries():
    paragraph = ("This is a complete sentence about licence coverage. " * 40).strip()
    chunks = split(paragraph)

    assert len(chunks) > 1
    assert all(len(chunk) <= MAX_CHUNK_CHARS + 200 for chunk in chunks)
    assert all(chunk.endswith(".") for chunk in chunks)


def test_empty_and_trivial_input_produce_no_chunks():
    assert split("") == []
    assert split("Heading only") == []


# --- reciprocal rank fusion ---------------------------------------------------


def _chunk(name: str, score: float, found_by: str):
    from app.repositories.corpusRepository import ScoredChunk

    return ScoredChunk(
        chunk_id=uuid.uuid5(uuid.NAMESPACE_OID, name),
        document_id=uuid.uuid4(),
        title=name,
        kind="policy",
        source_ref=None,
        content=name,
        score=score,
        found_by=(found_by,),
    )


def test_a_passage_both_retrievers_found_outranks_one_either_found_alone():
    """The entire reason to run two retrievers. Agreement is stronger evidence
    than confidence."""
    agreed = _chunk("agreed", 0.3, "vector")
    vector_only = _chunk("vector-only", 0.9, "vector")
    lexical_only = _chunk("lexical-only", 1.0, "lexical")

    fused = fuse(
        [vector_only, agreed],
        [lexical_only, _chunk("agreed", 0.5, "lexical")],
    )
    assert fused[0].title == "agreed"
    assert fused[0].found_by == ("lexical", "vector")


def test_fusion_reads_position_not_score():
    """Cosine sits around 0.2–0.4; term overlap saturates at exactly 1.0. Adding
    or averaging those two scales lets lexical dominate whenever it saturates,
    which is often — so fusion must ignore magnitude entirely."""
    weak_but_first = _chunk("first", 0.01, "vector")
    strong_but_second = _chunk("second", 0.99, "vector")

    fused = fuse([weak_but_first, strong_but_second])
    assert [item.title for item in fused] == ["first", "second"]


def test_fusion_of_nothing_is_empty_rather_than_an_error():
    assert fuse([], []) == []


# --- the corpus, end to end ---------------------------------------------------


@pytest.fixture
async def two_firms():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    session = async_sessionmaker(engine, expire_on_commit=False)()

    world = {}
    for name in ("a", "b"):
        org = Org(id=uuid.uuid4(), name=f"Firm {name.upper()}")
        session.add(org)
        await session.flush()
        client = Client(org_id=org.id, name=f"Client {name}")
        session.add(client)
        await session.flush()
        engagement = Engagement(
            org_id=org.id, client_id=client.id, title=f"E{name}", enabled_lanes=["sbom"]
        )
        session.add(engagement)
        await session.flush()
        world[name] = {"org": org, "engagement": engagement}
    await session.commit()

    yield session, world
    await session.close()
    await engine.dispose()


HOUSE_WORDING = """\
Licence coverage

Licences were absent across 388 of 412 components, failing 4.2(5). Partial \
coverage does not satisfy the clause: a declaration covering a quarter of the \
estate has not met it, and we do not report it as met.

We recommend the supplier restate their declaration with SPDX identifiers for \
every component, and resubmit. The gap register attached to this assessment \
lists each affected component.
"""


async def test_ingest_masks_before_it_writes(two_firms):
    session, world = two_firms
    repository = CorpusRepository(session, world["a"]["org"].id)

    report = await ingest(
        repository, kind="past_assessment", title="Acme Q1", text=HOUSE_WORDING
    )

    assert report.chunks == 2
    assert report.masked_facts >= 3

    stored = await repository.candidates()
    assert stored
    for chunk, _document in stored:
        assert residual_facts(chunk.content) == []
        assert "388" not in chunk.content
        assert "4.2(5)" not in chunk.content
        assert "⟨count⟩" in chunk.content or "⟨clause⟩" in chunk.content or chunk.masked_count == 0


async def test_the_wording_survives_even_though_the_figures_do_not():
    """Masking must not destroy what retrieval is for."""
    result = mask_facts(
        "Licences were absent across 388 of 412 components, failing 4.2(5)."
    )
    assert "Licences were absent across" in result.text
    assert "components, failing" in result.text


# --- tenancy: the property this component lives or dies on -------------------


async def test_another_firms_corpus_is_unreachable_even_when_it_matches_best(two_firms):
    """**The exit proof.** Firm B's corpus is seeded with the single best match
    for the query, so a missing scope predicate surfaces as the *first* result
    rather than hiding somewhere in the tail."""
    session, world = two_firms
    await ingest(
        CorpusRepository(session, world["b"]["org"].id),
        kind="past_assessment",
        title="Competitor — exact match",
        text=HOUSE_WORDING,
    )
    await ingest(
        CorpusRepository(session, world["a"]["org"].id),
        kind="policy",
        title="Ours — unrelated",
        text="The hardware asset register records serial numbers, warranty references "
        "and manufacturing locations for every deployed device in the estate.",
    )

    found = await retrieve(CorpusRepository(session, world["a"]["org"].id), "licence coverage")

    assert all("Competitor" not in passage.title for passage in found.passages)
    assert all(passage.kind != "past_assessment" for passage in found.passages)


async def test_a_firm_with_an_empty_corpus_retrieves_nothing_and_says_so(two_firms):
    """Reported rather than hidden: a drafter given nothing must say so rather
    than invent a house style."""
    session, world = two_firms
    found = await retrieve(CorpusRepository(session, world["a"]["org"].id), "licence coverage")

    assert found.passages == []
    assert found.corpus_empty


async def test_the_chunk_query_is_scoped_without_relying_on_the_join(two_firms):
    """`org_id` is denormalised onto the chunk precisely so the scope predicate
    applies to the chunk table itself. A join that is ever loosened must still not
    cross the boundary."""
    session, world = two_firms
    await ingest(
        CorpusRepository(session, world["b"]["org"].id),
        kind="policy",
        title="B",
        text=HOUSE_WORDING,
    )

    from app.models.corpus import CorpusChunk

    repository = CorpusRepository(session, world["a"]["org"].id)
    rows = (await session.execute(repository.scoped())).scalars().all()
    assert rows == []

    # The same query under B's scope does return them, so the empty result above
    # is the predicate working rather than an empty table.
    other = CorpusRepository(session, world["b"]["org"].id)
    assert (await session.execute(other.scoped())).scalars().all()
    assert CorpusChunk.org_id is not None


# --- hybrid beats either half alone ------------------------------------------


async def test_lexical_finds_the_exact_name_that_vector_search_misses(two_firms):
    """A query naming a specific component returns semantic neighbours from a
    vector search and never the paragraph that names the thing."""
    session, world = two_firms
    repository = CorpusRepository(session, world["a"]["org"].id)
    await ingest(
        repository,
        kind="remediation_wording",
        title="Tomcat",
        text="The declaration omits an entry for tomcat-catalina despite the build "
        "resolving it as a direct dependency of the application server module.",
    )
    await ingest(
        repository,
        kind="remediation_wording",
        title="Generic",
        text="Application servers and their bundled modules are frequently omitted "
        "from declarations because the build tool resolves them implicitly.",
    )

    lexical = await repository.lexical_ranked("tomcat-catalina")
    assert lexical
    assert lexical[0].title == "Tomcat"


async def test_hybrid_returns_both_kinds_of_hit(two_firms):
    session, world = two_firms
    repository = CorpusRepository(session, world["a"]["org"].id)
    await ingest(repository, kind="past_assessment", title="Licences", text=HOUSE_WORDING)
    await ingest(
        repository,
        kind="remediation_wording",
        title="Tomcat",
        text="The declaration omits an entry for tomcat-catalina despite the build "
        "resolving it as a direct dependency of the application server module.",
    )

    found = await retrieve(repository, "licences absent across the components")
    assert found.passages
    assert not found.corpus_empty
    assert all(passage.score > 0 for passage in found.passages)


async def test_an_engagements_own_prior_report_is_excluded_from_its_draft(two_firms):
    """Drafting this quarter's findings from last quarter's report restates the
    old text as new. It reads as continuity and is actually a copy."""
    session, world = two_firms
    repository = CorpusRepository(session, world["a"]["org"].id)
    engagement_id = world["a"]["engagement"].id

    await ingest(
        repository,
        kind="past_assessment",
        title="Same engagement, last quarter",
        text=HOUSE_WORDING,
        engagement_id=engagement_id,
    )

    without = await retrieve(repository, "licence coverage", exclude_engagement=engagement_id)
    with_it = await retrieve(repository, "licence coverage")

    assert without.passages == []
    assert with_it.passages


# --- generation, and the provenance boundary ---------------------------------


FACTS = "- s.4.2(5) Licence: absent, coverage 5.8%\n- overall verdict: fail"


def test_a_draft_restating_supplied_figures_is_accepted():
    verify("Licences fail 4.2(5); coverage stands at 5.8%.", facts=FACTS, section="Licence")


def test_a_draft_asserting_an_unsupplied_clause_is_refused():
    """A fabricated 4.2(4) *resolves* against the guideline perfectly. Resolution
    is not the property that matters here — provenance is."""
    with pytest.raises(UnsupportedFigure, match=r"4\.2\(4\)"):
        verify("Licences fail 4.2(4).", facts=FACTS, section="Licence")


def test_a_rounded_figure_is_refused():
    """The most likely single fabrication, and the hardest to notice: 5.8 becomes
    6 and the sentence still reads correctly."""
    with pytest.raises(UnsupportedFigure, match="6%"):
        verify("Coverage stands at roughly 6%.", facts=FACTS, section="Licence")


def test_an_invented_cve_is_refused():
    with pytest.raises(UnsupportedFigure, match="CVE-2021-44228"):
        verify("The component is exposed to CVE-2021-44228.", facts=FACTS, section="Licence")


def test_a_dropped_clause_prefix_is_not_treated_as_fabrication():
    """`s.4.2(5)` in the facts covers `4.2(5)` in the draft. Refusing a formatting
    choice would train everyone to disable the check."""
    verify("Clause 4.2(5) is unmet.", facts=FACTS, section="Licence")


def test_counts_in_prose_are_not_checked():
    """"three lanes" and "one supplier" are English, not claims about this
    assessment. A rule refusing every digit would refuse every draft."""
    verify("Three of the five lanes reported findings.", facts=FACTS, section="Licence")


async def test_the_null_generator_restates_facts_rather_than_inventing_prose(two_firms):
    """No provider configured is a state, not a crash. A client reading flat
    facts gets correct information; a client reading hallucinated prose gets
    fluent text that may be wrong and cannot tell."""
    session, world = two_firms
    repository = CorpusRepository(session, world["a"]["org"].id)

    section = await draft_section(repository, section="Licence coverage", facts=FACTS)

    assert not section.drafted
    assert section.generator == "none"
    assert "4.2(5)" in section.content
    assert "not configured" in section.content


async def test_a_drafted_section_is_verified_against_its_facts(two_firms):
    """The boundary, exercised through the real path with a generator that
    fabricates — which is what a real one does occasionally."""
    session, world = two_firms
    repository = CorpusRepository(session, world["a"]["org"].id)

    class Fabricating(Generator):
        name = "fabricating-test-double"
        available = True

        def complete(self, system: str, user: str, *, max_words: int) -> str:
            return "Coverage stands at 91.4%, comfortably meeting 4.2(9)."

    with pytest.raises(UnsupportedFigure, match="Licence coverage"):
        await draft_section(
            repository, section="Licence coverage", facts=FACTS, generator=Fabricating()
        )


async def test_a_faithful_generator_passes_the_boundary(two_firms):
    session, world = two_firms
    repository = CorpusRepository(session, world["a"]["org"].id)

    class Faithful(Generator):
        name = "faithful-test-double"
        available = True

        def complete(self, system: str, user: str, *, max_words: int) -> str:
            return "Licence declarations are unmet under 4.2(5), with coverage at 5.8%."

    section = await draft_section(
        repository, section="Licence coverage", facts=FACTS, generator=Faithful()
    )
    assert section.drafted
    assert section.generator == "faithful-test-double"


async def test_retrieved_house_wording_reaches_the_prompt_masked(two_firms):
    """The reason showing a model another client's prose is safe at all."""
    session, world = two_firms
    repository = CorpusRepository(session, world["a"]["org"].id)
    await ingest(repository, kind="house_style", title="House", text=HOUSE_WORDING)

    captured: dict[str, str] = {}

    class Capturing(Generator):
        name = "capturing"
        available = False

        def complete(self, system: str, user: str, *, max_words: int) -> str:
            captured["user"] = user
            return NullGenerator().complete(system, user, max_words=max_words)

    await draft_section(
        repository, section="Licence coverage", facts=FACTS, generator=Capturing()
    )

    house = captured["user"].split("HOUSE WORDING", 1)[1]
    assert "388" not in house
    assert "412" not in house
    assert "⟨count⟩" in house


def test_the_prompt_forbids_deriving_a_figure():
    """The instruction exists so the model has a chance of complying; `verify`
    exists because it might not."""
    from app.services.graph.prompts.sectionDrafter import SYSTEM

    lowered = SYSTEM.lower()
    assert "must appear verbatim" in lowered
    assert "may not derive" in lowered
    assert "placeholders" in lowered
    assert "not_determinable" in lowered


def test_builder_holds_no_prompt_text_and_imports_none():
    """`services/graph/builder.py` is pure wiring.

    Checked on the AST, not on the source text — the first version of this test
    grepped for "prompts" and failed on builder.py's own docstring explaining that
    prompts live elsewhere. That is the third time a test in this repository has
    matched its own documentation; identifiers only.
    """
    import ast
    from pathlib import Path

    tree = ast.parse((Path(__file__).parent.parent / "app/services/graph/builder.py").read_text())

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            assert "prompts" not in node.module.split("."), (
                f"builder.py imports prompt text from {node.module}"
            )
        # A prompt is a long string literal. Docstrings are exempt; they are
        # documentation, which is the thing the previous version tripped over.
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if len(node.value) > 400 and node not in _docstrings(tree):
                pytest.fail("builder.py carries a long string literal — prompts are data")


def _docstrings(tree: ast.AST) -> set:
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                found.add(body[0].value)
    return found


# --- the completion provider -------------------------------------------------


def test_the_provider_is_off_by_default():
    """The safe default rather than a timid one: with narrative drafting off, a
    section still carries its findings, restated by the engine."""
    from app.configs.envConfig import settings

    assert settings.NARRATIVE_ENABLED is False


def test_a_placeholder_key_is_recognised_by_the_missing_prefix():
    """`ANTHROPIC_API_KEY` is a *required* config var, so it is never absent —
    tests, CI and `make demo` all set something. A blocklist of the placeholder
    spellings we happen to know about misses the next one somebody invents, and
    the failure mode is a live provider call from the test suite."""
    from app.services.llm.anthropicClient import GenerationUnavailable, _client

    with pytest.raises(GenerationUnavailable, match="sk-ant-"):
        _client()


def test_the_suite_cannot_reach_a_provider(monkeypatch):
    """The guarantee that matters for a test suite: enabled or not, the key here
    is a placeholder, so no code path constructs a live client."""
    from app.configs.envConfig import settings
    from app.services.llm.anthropicClient import AnthropicGenerator

    monkeypatch.setattr(settings, "NARRATIVE_ENABLED", True)
    assert AnthropicGenerator().available is False


def test_the_active_generator_degrades_rather_than_raising():
    """A deployment without a provider must draft nothing, not crash."""
    from app.services.llm.anthropicClient import active_generator
    from app.services.narrative.generator import NullGenerator

    assert isinstance(active_generator(), NullGenerator)


def test_a_refusal_is_read_before_the_content_list(monkeypatch):
    """A refusal returns HTTP 200 with an empty content list. Indexing straight
    into it raises an IndexError that reads as a bug rather than as the policy
    decision it is."""
    from app.configs.envConfig import settings
    from app.services.llm import anthropicClient
    from app.services.llm.anthropicClient import AnthropicGenerator, GenerationUnavailable

    class _Refused:
        stop_reason = "refusal"
        stop_details = type("D", (), {"category": "cyber"})()
        content: list = []

    class _Messages:
        def create(self, **kwargs):
            return _Refused()

    class _Client:
        beta = type("B", (), {"messages": _Messages()})()

    monkeypatch.setattr(settings, "NARRATIVE_ENABLED", True)
    monkeypatch.setattr(anthropicClient, "_client", lambda: _Client())

    with pytest.raises(GenerationUnavailable, match="declined"):
        AnthropicGenerator().complete("sys", "user", max_words=200)


def test_the_request_carries_no_sampling_parameters(monkeypatch):
    """`temperature`, `top_p` and `top_k` are rejected on this model family.
    Asserted on the outgoing request rather than trusted, because the failure is
    a 400 at the first real call — in production, not in the suite."""
    from app.configs.envConfig import settings
    from app.services.llm import anthropicClient
    from app.services.llm.anthropicClient import AnthropicGenerator

    captured: dict = {}

    class _Block:
        type = "text"
        text = "Licences fail 4.2(5)."

    class _Response:
        stop_reason = "end_turn"
        model = "claude-opus-5"
        content = [_Block()]
        usage = type("U", (), {"input_tokens": 10, "output_tokens": 5})()

    class _Messages:
        def create(self, **kwargs):
            captured.update(kwargs)
            return _Response()

    class _Client:
        beta = type("B", (), {"messages": _Messages()})()

    monkeypatch.setattr(settings, "NARRATIVE_ENABLED", True)
    monkeypatch.setattr(anthropicClient, "_client", lambda: _Client())

    AnthropicGenerator().complete("sys", "user", max_words=200)

    for rejected in ("temperature", "top_p", "top_k"):
        assert rejected not in captured
    assert captured["thinking"] == {"type": "adaptive"}
    assert captured["model"] == "claude-opus-5"
    assert captured["max_tokens"] >= 4000


def test_a_fallback_is_requested_so_one_declined_section_does_not_fail(monkeypatch):
    """Assessment prose about vulnerabilities is exactly the security-adjacent
    content a classifier occasionally declines."""
    from app.configs.envConfig import settings
    from app.services.llm import anthropicClient
    from app.services.llm.anthropicClient import AnthropicGenerator

    captured: dict = {}

    class _Block:
        type = "text"
        text = "ok"

    class _Response:
        stop_reason = "end_turn"
        model = "claude-opus-5"
        content = [_Block()]
        usage = type("U", (), {"input_tokens": 1, "output_tokens": 1})()

    class _Messages:
        def create(self, **kwargs):
            captured.update(kwargs)
            return _Response()

    class _Client:
        beta = type("B", (), {"messages": _Messages()})()

    monkeypatch.setattr(settings, "NARRATIVE_ENABLED", True)
    monkeypatch.setattr(anthropicClient, "_client", lambda: _Client())

    AnthropicGenerator().complete("sys", "user", max_words=200)
    assert captured["fallbacks"] == "default"
    assert "server-side-fallback-2026-07-01" in captured["betas"]


def test_sdk_errors_are_matched_by_class_not_by_message():
    """The SDK defines a distinct exception per status precisely so callers do
    not string-match. A message match breaks silently when the wording improves."""
    import anthropic
    import httpx

    from app.services.llm.anthropicClient import GenerationUnavailable, _translate

    request = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    not_found = anthropic.NotFoundError(
        "any wording at all",
        response=httpx.Response(404, request=request),
        body=None,
    )
    translated = _translate(not_found)

    assert isinstance(translated, GenerationUnavailable)
    assert "NARRATIVE_MODEL" in str(translated)


async def test_a_drafted_section_still_passes_the_provenance_boundary(two_firms, monkeypatch):
    """The point of wiring a model in at all: nothing about §11 relaxes. A real
    provider's output is checked exactly as the test double's was."""
    from app.configs.envConfig import settings
    from app.services.llm import anthropicClient
    from app.services.llm.anthropicClient import AnthropicGenerator

    session, world = two_firms

    class _Block:
        type = "text"
        text = "Coverage reached 91.4% against 4.2(9)."  # neither figure supplied

    class _Response:
        stop_reason = "end_turn"
        model = "claude-opus-5"
        content = [_Block()]
        usage = type("U", (), {"input_tokens": 1, "output_tokens": 1})()

    class _Client:
        beta = type(
            "B", (), {"messages": type("M", (), {"create": lambda self, **kw: _Response()})()}
        )()

    monkeypatch.setattr(settings, "NARRATIVE_ENABLED", True)
    monkeypatch.setattr(anthropicClient, "_client", lambda: _Client())

    with pytest.raises(UnsupportedFigure):
        await draft_section(
            CorpusRepository(session, world["a"]["org"].id),
            section="Licence coverage",
            facts=FACTS,
            generator=AnthropicGenerator(),
        )
