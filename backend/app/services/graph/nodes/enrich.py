"""Fill the four ENRICH fields from the feeds, then re-score.

Runs **after** the join, deliberately. Scoring the supplier's own declarations
first and enriching afterwards keeps the two claims separable: the assessment can
say "the supplier declared 3 of 21 fields; we enriched a further 4 from NVD and
endoflife.date" rather than presenting a single blended number that flatters
everyone.

**Deterministic feeds run first and answer most components.** Only what they miss
becomes an agent batch, keyed per distinct product. The split is reported, since
a reader is entitled to know which facts were looked up deterministically and
which were researched.

A feed that is down is a reported gap. It never becomes an empty vulnerability
list, because an empty list is a claim — "we checked and there is nothing" — and
we would not be entitled to make it.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx

from app.configs.envConfig import settings
from app.configs.jobTypes import LaneVerdict
from app.configs.scoringConfig import ENGINE_VERSION
from app.services.catalogue.loader import catalogue_checksum, get_catalogue
from app.services.graph.nodes.sbomLane import _as_row
from app.services.graph.state import GraphState, LaneResult, NodeRun
from app.services.kb import eolClient, kevClient, nvdClient
from app.services.kb.base import FeedUnavailable
from app.services.kb.enrichment import (
    EnrichmentOutcome,
    apply_lifecycle,
    apply_vulnerabilities,
    batch_key_for,
    summarise,
)
from app.services.score.documentChecks import check_all, document_metadata
from app.services.score.verdict import lane_verdict
from app.services.score.weighting import lane_score
from app.utils.logger import get_logger

logger = get_logger(__name__)

#: Bounds the deterministic pass. Beyond this the feeds are the bottleneck and
#: the remainder is better handled as agent batches than as thousands of calls.
MAX_PRODUCT_LOOKUPS = 60


def _lane(state: GraphState, lane: str) -> LaneResult | None:
    return next(
        (result for result in state.get("lane_results", []) if result.lane == lane), None
    )


async def _kev_index(client: httpx.AsyncClient, outcome: EnrichmentOutcome) -> dict[str, Any]:
    try:
        entries = await kevClient.fetch_catalog(client=client)
        outcome.sources_used.add("cisa-kev")
        return kevClient.index_by_cve(entries)
    except FeedUnavailable as error:
        # Reported, not swallowed. Without KEV we cannot say a CVE is *not*
        # KEV-listed, so the absence is recorded rather than implied.
        outcome.unavailable["cisa-kev"] = str(error)
        logger.warning("kev_unavailable", error=str(error))
        return {}


async def _enrich_product(
    client: httpx.AsyncClient,
    product: str,
    entities: list[dict[str, Any]],
    kev_index: dict[str, Any],
    outcome: EnrichmentOutcome,
) -> None:
    """Enrich every entity of one product with one set of lookups."""
    sample = entities[0]
    name = str(sample.get("name") or "")

    # --- lifecycle (4.2(9), 4.2(10), 4.2(11)) ------------------------------
    slug = eolClient.slug_for(name)
    cycles: list[dict[str, Any]] = []
    if slug:
        try:
            cycles = await eolClient.cycles_for(slug, client=client)
            if cycles:
                outcome.sources_used.add("endoflife.date")
        except FeedUnavailable as error:
            outcome.unavailable.setdefault("endoflife.date", str(error))

    if not cycles:
        # The feed does not track this product. That is the agent's job, and it
        # is queued per product rather than per component.
        outcome.agent_batch.add(product)

    # --- vulnerabilities (4.2(8)) ------------------------------------------
    cves: list[dict[str, Any]] = []
    if cpe := sample.get("cpe"):
        try:
            cves = await nvdClient.by_cpe(str(cpe), client=client)
            outcome.sources_used.add("nvd")
        except FeedUnavailable as error:
            outcome.unavailable.setdefault("nvd", str(error))

    for entity in entities:
        applied = apply_lifecycle(entity, cycles) if cycles else {}
        if cves and (value := apply_vulnerabilities(entity, cves, kev_index=kev_index)):
            applied["vulnerabilities"] = value
        if applied:
            outcome.enriched += 1
        else:
            outcome.unresolved.append(str(entity.get("name")))


async def enrich(state: GraphState) -> GraphState:
    """Enrich the SBOM lane's entities, then re-score it."""
    started_at = datetime.now(UTC)
    sbom = _lane(state, "sbom")

    # Enrich only a lane that actually carried entities. That single condition
    # covers absent, timed-out, not-applicable *and* failed lanes uniformly, and
    # the last one matters most: re-scoring a crashed lane would produce 0.0 and
    # turn an infrastructure failure into a supplier verdict of zero — the same
    # error §11 forbids when it excludes lane_timeout from the overall score.
    if sbom is None or not sbom.entities:
        if sbom is not None and sbom.verdict is LaneVerdict.FAIL:
            logger.info(
                "enrichment_skipped",
                reason="the sbom lane carried no entities; its verdict stands",
                verdict=str(sbom.verdict),
            )
        return GraphState(
            node_runs=[
                NodeRun(
                    node="enrich",
                    status="succeeded",
                    started_at=started_at,
                    finished_at=datetime.now(UTC),
                )
            ]
        )

    entities = list(sbom.entities)
    outcome = EnrichmentOutcome()

    products: dict[str, list[dict[str, Any]]] = {}
    for entity in entities:
        products.setdefault(batch_key_for(entity), []).append(entity)

    logger.info(
        "enrichment_started",
        components=len(entities),
        distinct_products=len(products),
    )

    if not settings.ENRICHMENT_ONLINE:
        # Offline: every product becomes an agent batch, which is the honest
        # outcome — we did not look, so we know nothing, and the four ENRICH
        # fields keep whatever the supplier declared.
        outcome.unavailable["all"] = "ENRICHMENT_ONLINE is off; no feed was queried"
        outcome.agent_batch.update(products)
        logger.info("enrichment_offline", products=len(products))
    else:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            kev_index = await _kev_index(client, outcome)

            # Sequential per product: the feeds rate-limit, and a burst of
            # parallel requests earns a block that degrades the next assessment.
            for product, group in list(products.items())[:MAX_PRODUCT_LOOKUPS]:
                try:
                    await _enrich_product(client, product, group, kev_index, outcome)
                except FeedUnavailable as error:
                    outcome.unavailable.setdefault(error.feed, str(error))
                except Exception as error:  # noqa: BLE001 - never fails a lane
                    logger.warning(
                        "enrichment_product_failed", product=product, error=str(error)
                    )
                    outcome.agent_batch.add(product)

    if len(products) > MAX_PRODUCT_LOOKUPS:
        for product in list(products)[MAX_PRODUCT_LOOKUPS:]:
            outcome.agent_batch.add(product)

    # --- re-score with the enriched entities -------------------------------
    catalogue = get_catalogue("sbom")
    documents = [document_metadata(author=None, timestamp=None)]
    if sbom.field_results:
        # Preserve the document-scoped answers the lane already established.
        author_row = next(
            (row for row in sbom.field_results if row["element_key"] == "author_name"), None
        )
        timestamp_row = next(
            (row for row in sbom.field_results if row["element_key"] == "timestamp"), None
        )
        documents = [
            document_metadata(
                author="preserved" if author_row and author_row["populated"] else None,
                timestamp="preserved" if timestamp_row and timestamp_row["populated"] else None,
            )
        ]

    results = check_all(catalogue, entities, documents)
    score = lane_score(results)
    verdict, detail = lane_verdict(score, results)

    delta = round(score - (sbom.score or 0.0), 2)
    summary = summarise(outcome)
    logger.info("enrichment_complete", score_before=sbom.score, score_after=score, **summary)

    rescored = LaneResult(
        lane="sbom",
        verdict=verdict,
        score=score,
        entity_count=len(entities),
        detail=(
            f"{detail}; enriched {outcome.enriched} component(s) from "
            f"{', '.join(sorted(outcome.sources_used)) or 'no feed'} "
            f"({delta:+} points), {len(outcome.agent_batch)} product(s) queued for research"
        ),
        engine_version=ENGINE_VERSION,
        inputs_hash=catalogue_checksum("sbom"),
        field_results=[_as_row(item) for item in results],
        rejected_count=sbom.rejected_count,
        entities=entities,
    )

    return GraphState(
        lane_results=[rescored],
        node_runs=[
            NodeRun(
                node="enrich",
                status="succeeded",
                started_at=started_at,
                finished_at=datetime.now(UTC),
            )
        ],
    )
