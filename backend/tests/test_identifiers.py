"""S11: the CERT-In identifier, the registry ladder, and the resolver agent.

The headline is Table 3's worked example, asserted exactly. The rest of the file
is about the ways a resolver can be confidently wrong, and refusing each.
"""

from __future__ import annotations

import pytest

from app.services.agents.loop import Retrieved
from app.services.agents.supplierResolver import (
    confirm,
    gate,
    plan_query,
    resolve_suppliers,
)
from app.services.identifiers.purl import (
    InvalidPurl,
    is_certin,
    normalise_organisation,
    parse,
    to_certin,
    try_parse,
)
from app.services.identifiers.successors import (
    SuccessorCycle,
    historical_names,
    resolve_current,
)
from app.services.identifiers.supplierRegistry import (
    Source,
    organisation_from_namespace,
    resolve,
    summarise,
    unresolved_coordinates,
)
from app.validators.figureProvenanceValidator import (
    FigureNotTraceable,
    assert_figures_traceable,
    figures_in,
)

# --- Table 3, the worked example --------------------------------------------


def test_the_table_3_worked_example_converts_exactly():
    """The §S11 exit proof, verbatim from the guideline."""
    source = "pkg:maven/org.apache.tomcat/tomcat-catalina@9.0.71"
    assert (
        to_certin(source, organisation="Apache Software Foundation")
        == "pkg:supplier/ApacheSoftwareFoundation/tomcat-catalina@9.0.71"
    )


def test_supplier_is_not_a_registered_purl_type_so_nothing_emits_it():
    """The reason 4.2(21) is absent on every real-world BOM until a registry
    exists: no generator produces this type."""
    generated = parse("pkg:maven/org.apache.tomcat/tomcat-catalina@9.0.71")
    assert generated.type == "maven"
    assert not is_certin(generated.to_string())
    assert is_certin(to_certin(generated, organisation="Apache Software Foundation"))


@pytest.mark.parametrize(
    "value",
    [
        "pkg:maven/org.apache.tomcat/tomcat-catalina@9.0.71",
        "pkg:npm/express@4.18.0",
        "pkg:npm/%40angular/core@17.0.0",
        "pkg:pypi/django@4.2.1",
        "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
    ],
)
def test_purls_round_trip(value):
    assert parse(value).to_string() == value


def test_a_malformed_purl_raises_rather_than_returning_a_partial():
    for bad in ["", "not-a-purl", "pkg:", "http://example.com/x"]:
        with pytest.raises(InvalidPurl):
            parse(bad)
    assert try_parse("not-a-purl") is None


def test_coordinates_are_versionless():
    """Supplier identity belongs to the product: Tomcat 9 and 10 share a
    foundation, and keying per version would multiply the curated dataset by
    every release."""
    nine = parse("pkg:maven/org.apache.tomcat/tomcat-catalina@9.0.71")
    ten = parse("pkg:maven/org.apache.tomcat/tomcat-catalina@10.1.0")
    assert nine.coordinates == ten.coordinates


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Apache Software Foundation", "ApacheSoftwareFoundation"),
        ("Red Hat, Inc.", "RedHatInc"),
        ("The Linux Foundation", "TheLinuxFoundation"),
        ("Eclipse Foundation AISBL", "EclipseFoundationAISBL"),
        ("openjs foundation", "OpenjsFoundation"),
    ],
)
def test_organisation_names_normalise_consistently(raw, expected):
    """Two spellings of one organisation must not become two identifiers."""
    assert normalise_organisation(raw) == expected


def test_building_an_identifier_requires_an_organisation():
    """No default and no inference: a fallback would silently emit a confident
    wrong identifier for every unresolved component."""
    with pytest.raises(ValueError, match="organisation name is required"):
        to_certin("pkg:npm/express@4.18.0", organisation="")


# --- the deterministic ladder ------------------------------------------------


def test_a_curated_entry_wins_with_full_confidence():
    resolution = resolve(
        {"name": "tomcat-catalina", "version": "9.0.71",
         "purl": "pkg:maven/org.apache.tomcat/tomcat-catalina@9.0.71"},
        registry={"maven/org.apache.tomcat/tomcat-catalina": "Apache Software Foundation"},
    )
    assert resolution.source is Source.CURATED
    assert resolution.confidence == 1.0
    assert resolution.certin_id == "pkg:supplier/ApacheSoftwareFoundation/tomcat-catalina@9.0.71"


def test_a_declared_supplier_is_trusted_below_a_curated_entry():
    resolution = resolve(
        {"name": "express", "version": "4.18.0", "purl": "pkg:npm/express@4.18.0",
         "supplier_raw": "OpenJS Foundation"}
    )
    assert resolution.source is Source.DECLARED_SUPPLIER
    assert resolution.confidence == 0.8


def test_a_purl_namespace_is_inference_and_marked_as_such():
    resolution = resolve(
        {"name": "tomcat-catalina", "version": "9.0.71",
         "purl": "pkg:maven/org.apache.tomcat/tomcat-catalina@9.0.71"}
    )
    assert resolution.source is Source.PURL_NAMESPACE
    assert resolution.confidence == 0.5
    assert "not verified" in resolution.reason


def test_the_ladder_is_ordered_by_how_much_a_human_verified():
    from app.services.identifiers.supplierRegistry import CONFIDENCE

    assert (
        CONFIDENCE[Source.CURATED]
        > CONFIDENCE[Source.DECLARED_SUPPLIER]
        > CONFIDENCE[Source.PURL_NAMESPACE]
        > CONFIDENCE[Source.UNRESOLVED]
    )


# --- the refusals that matter ------------------------------------------------


def test_an_unresolvable_component_reports_absent_not_a_guess():
    """The §S11 exit proof. A plausible-looking wrong identifier is worse than a
    gap the client can see and chase."""
    resolution = resolve({"name": "mystery-lib", "version": "1.0.0"})

    assert resolution.source is Source.UNRESOLVED
    assert resolution.certin_id is None
    assert resolution.supplier_org is None
    assert "rather than emitting a plausible-looking wrong identifier" in resolution.reason


def test_a_declared_supplier_that_is_a_handle_is_refused():
    """`azer` is a real npm publisher name. It is a person, not an organisation."""
    resolution = resolve(
        {"name": "leftpad", "version": "1.0.0", "purl": "pkg:npm/leftpad@1.0.0",
         "supplier_raw": "azer"}
    )
    assert resolution.source is Source.UNRESOLVED
    assert resolution.certin_id is None
    assert "bare handle" in resolution.reason


@pytest.mark.parametrize(
    "namespace",
    ["com.github.someone", "io.github.someone", "com.gitlab.person"],
)
def test_a_personal_namespace_never_becomes_an_organisation(namespace):
    """A GitHub namespace names an account, and an account is not a supplier."""
    assert organisation_from_namespace(parse(f"pkg:maven/{namespace}/thing@1.0")) is None
    resolution = resolve({"name": "thing", "purl": f"pkg:maven/{namespace}/thing@1.0"})
    assert resolution.source is Source.UNRESOLVED


def test_namespace_inference_strips_only_meaningless_prefixes():
    assert organisation_from_namespace(parse("pkg:maven/org.apache.tomcat/x@1")) == "apache"
    assert organisation_from_namespace(parse("pkg:npm/%40angular/core@17")) == "angular"


def test_unresolved_coordinates_are_batched_per_product():
    """Two versions of one product are one research question."""
    resolutions = [
        resolve({"name": "a", "purl": "pkg:maven/com.github.x/a@1.0"}),
        resolve({"name": "a", "purl": "pkg:maven/com.github.x/a@2.0"}),
        resolve({"name": "b", "version": "1.0"}),
    ]
    assert len(unresolved_coordinates(resolutions)) == 2


def test_summary_reports_the_resolution_split():
    resolutions = [
        resolve({"name": "x", "purl": "pkg:npm/x@1", "supplier_raw": "Acme Foundation"}),
        resolve({"name": "y", "version": "1"}),
    ]
    summary = summarise(resolutions)
    assert summary["total"] == 2
    assert summary["resolved"] == 1


# --- successors (Table 4) ----------------------------------------------------


def test_a_rebrand_chain_resolves_to_the_current_organisation():
    """Table 4's rationale: the identifier must survive acquisition."""
    links = {"Sun Microsystems": "Oracle Corporation"}
    current, chain = resolve_current("Sun Microsystems", links)
    assert current == "Oracle Corporation"
    assert chain == ["Sun Microsystems", "Oracle Corporation"]


def test_a_multi_step_chain_walks_to_the_end():
    links = {"A Ltd": "B Inc", "B Inc": "C Corporation"}
    current, chain = resolve_current("A Ltd", links)
    assert current == "C Corporation"
    assert len(chain) == 3


def test_a_looping_chain_is_reported_rather_than_hung_on():
    """Acquisitions get recorded from both directions; a loop must not hang."""
    with pytest.raises(SuccessorCycle, match="loops"):
        resolve_current("A", {"A": "B", "B": "A"})


def test_predecessors_are_findable_for_matching_old_boms():
    links = {"Sun Microsystems": "Oracle Corporation", "BEA Systems": "Oracle Corporation"}
    assert historical_names("Oracle Corporation", links) == ["BEA Systems", "Sun Microsystems"]


# --- the resolver agent ------------------------------------------------------


def _retriever(candidate, snippet="", url="https://example.org/governance"):
    async def retrieve(query: str) -> Retrieved:
        return Retrieved(url=url, snippet=snippet or str(candidate), candidate=candidate)

    return retrieve


async def test_a_personal_github_account_is_rejected_not_published():
    """The §S11 exit proof, and the reason the sufficiency check exists."""
    proposals, _ = await resolve_suppliers(
        ["npm/leftpad"], retriever=_retriever("github.com/azer")
    )
    proposal = proposals[0]

    assert proposal.proposed_supplier is None
    assert proposal.status == "rejected"
    assert not proposal.proposal.is_actionable


async def test_an_organisation_is_proposed_with_its_evidence():
    proposals, _ = await resolve_suppliers(
        ["maven/org.apache.tomcat/tomcat-catalina"],
        retriever=_retriever("Apache Software Foundation"),
    )
    proposal = proposals[0]

    assert proposal.proposed_supplier == "Apache Software Foundation"
    assert proposal.status == "pending"
    row = proposal.as_row()
    assert row["evidence"]
    assert row["evidence"][0]["source_url"]


async def test_the_agent_output_is_a_proposal_never_a_registry_write():
    """§11: agents research; they never decide. The agent has no path to the
    curated table — promotion is a separate, human function."""
    proposals, _ = await resolve_suppliers(
        ["npm/x"], retriever=_retriever("Example Foundation")
    )
    assert proposals[0].status == "pending"

    entry = confirm(proposals[0], reviewed_by="analyst@firm.example")
    assert entry["source"] == "curated"
    assert entry["confidence"] == 1.0
    assert entry["verified_by"] == "analyst@firm.example"


async def test_a_rejected_proposal_cannot_be_confirmed():
    proposals, _ = await resolve_suppliers(["npm/y"], retriever=_retriever("torvalds"))
    with pytest.raises(ValueError, match="sufficiency check rejected"):
        confirm(proposals[0], reviewed_by="analyst@firm.example")


async def test_confirming_a_proposal_grows_the_curated_asset():
    """The compounding property: one confirmation improves every future
    submission, which is the point of the sprint."""
    registry: dict[str, str] = {}
    proposals, _ = await resolve_suppliers(
        ["maven/org.apache.tomcat/tomcat-catalina"],
        retriever=_retriever("Apache Software Foundation"),
    )
    entry = confirm(proposals[0], reviewed_by="analyst")
    registry[entry["namespace_or_name"]] = entry["supplier_org"]

    # The same component now resolves deterministically, with full confidence.
    resolution = resolve(
        {"name": "tomcat-catalina", "version": "9.0.71",
         "purl": "pkg:maven/org.apache.tomcat/tomcat-catalina@9.0.71"},
        registry=registry,
    )
    assert resolution.source is Source.CURATED
    assert resolution.confidence == 1.0


async def test_the_resolver_batches_per_coordinate():
    proposals, report = await resolve_suppliers(
        ["npm/a", "npm/b"],
        retriever=_retriever("Acme Foundation"),
        components_per_key={"npm/a": 1200, "npm/b": 800},
    )
    table = report.as_table()
    assert table["batches"] == 2
    assert table["components_covered"] == 2000


def test_the_planner_changes_angle_between_hops():
    first = plan_query("npm/express", None)
    second = plan_query("npm/express", "governance page or trademark owner")
    assert first != second
    assert "governance" in second


def test_the_gate_refuses_an_empty_retrieval_with_a_next_angle():
    verdict = gate("npm/x", Retrieved(url=None, snippet="", candidate=None))
    assert not verdict.sufficient
    assert verdict.next_angle


# --- figure provenance -------------------------------------------------------


class _Lane:
    def __init__(self, score, rows):
        self.score = score
        self.field_results = rows


def test_prose_may_restate_a_computed_figure():
    lane = _Lane(43.9, [{"coverage": 0.03, "total": 400, "populated": 12}])
    assert_figures_traceable(
        "The SBOM scored 43.9%, with licences on 3% of 400 components.",
        lane_results=[lane],
    )


def test_an_invented_figure_blocks_the_render():
    """The §S11 exit proof: a drafter writing 92% where no lane holds it."""
    lane = _Lane(43.9, [{"coverage": 0.03, "total": 400, "populated": 12}])
    with pytest.raises(FigureNotTraceable, match="92"):
        assert_figures_traceable("Overall conformance reached 92%.", lane_results=[lane])


def test_the_message_states_the_rule_it_enforces():
    lane = _Lane(43.9, [])
    with pytest.raises(FigureNotTraceable, match="may not produce one"):
        assert_figures_traceable("A score of 88 was achieved.", lane_results=[lane])


def test_rounding_within_tolerance_is_accepted():
    lane = _Lane(43.92, [])
    assert_figures_traceable("scored 43.9%", lane_results=[lane])


def test_clause_references_and_dates_are_not_treated_as_figures():
    """Not every number is a figure: clauses, CVEs and dates contain digits."""
    assert figures_in("clause 4.2(5) and CVE-2021-44228 dated 2024-10-07") == []
