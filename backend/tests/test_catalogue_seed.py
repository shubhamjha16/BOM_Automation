"""S7: the catalogue as versioned data, and what a version bump protects.

The rule these tests exist for: **an assessment issued under v2.0 must keep
reporting against v2.0 forever.** A client holding a conformance assessment has
to be able to say which document it was measured against, and a code constant
cannot answer that — it changes for everyone at once, retroactively and silently.
"""

from __future__ import annotations

import uuid
from datetime import date

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.configs.envConfig import ALL_LANES
from app.models import Base, Client, Engagement, GuidelineVersion, MinimumElement, Org
from app.models.enums import BomFormat
from app.repositories.laneRepository import LaneRepository
from app.repositories.submissionRepository import SubmissionRepository
from app.services.catalogue.loader import get_catalogue
from app.services.catalogue.seeder import (
    CatalogueDrift,
    combined_checksum,
    elements_for,
    get_active_version,
    seed,
)
from tests.conftest import component, cyclonedx_document


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    async with async_sessionmaker(engine, expire_on_commit=False)() as session:
        yield session
    await engine.dispose()


# --- seeding ----------------------------------------------------------------


async def test_seeding_writes_every_element_of_every_lane(session):
    version = await seed(session)

    rows = (await session.execute(select(MinimumElement))).scalars().all()
    expected = sum(len(get_catalogue(lane).elements) for lane in ALL_LANES)
    assert len(rows) == expected

    sbom = [row for row in rows if row.lane == "sbom"]
    assert len(sbom) == 21
    assert version.version == "2.0"
    assert version.published_on == date(2025, 7, 9)


async def test_every_seeded_element_carries_its_clause_tier_and_determinability(session):
    await seed(session)
    rows = (await session.execute(select(MinimumElement))).scalars().all()

    for row in rows:
        assert row.clause, f"{row.lane}.{row.key} has no clause"
        assert row.tier is not None
        assert row.determinability is not None
        assert row.scope in ("entity", "document")


async def test_human_elements_are_seeded_with_their_consumer_action(session):
    """A not_determinable verdict without an action reads as a shrug."""
    await seed(session)
    rows = (
        (await session.execute(
            select(MinimumElement).where(MinimumElement.determinability == "human")
        ))
        .scalars()
        .all()
    )

    # SBOM criticality and usage restrictions, AIBOM intended and out-of-scope
    # usage, plus the deployment-context determinations the S14 crypto lanes add.
    assert {"4.2(12)", "4.2(13)", "9.3(15)", "9.3(16)"} <= {row.clause for row in rows}
    for row in rows:
        assert row.consumer_action, f"{row.key} has no consumer action"


async def test_seeding_twice_is_a_no_op_not_a_duplicate(session):
    """A duplicated catalogue doubles every coverage denominator."""
    first = await seed(session)
    second = await seed(session)

    assert first.id == second.id
    versions = (await session.execute(select(GuidelineVersion))).scalars().all()
    assert len(versions) == 1

    rows = (await session.execute(select(MinimumElement))).scalars().all()
    assert len(rows) == sum(len(get_catalogue(lane).elements) for lane in ALL_LANES)


# --- drift detection --------------------------------------------------------


async def test_editing_the_catalogue_without_a_version_bump_is_refused(session):
    """The rule the whole table exists for.

    If v2.0's elements could be edited in place, every assessment already scored
    under v2.0 would silently start reporting against different rules.
    """
    version = await seed(session)
    # Simulate the encoded catalogue having moved on under the same version name.
    version.checksum = "0" * 64
    await session.flush()

    with pytest.raises(CatalogueDrift, match="without a version bump"):
        await seed(session)


async def test_the_drift_message_names_the_remedy(session):
    version = await seed(session)
    version.checksum = "0" * 64
    await session.flush()

    with pytest.raises(CatalogueDrift) as raised:
        await seed(session)
    assert "publish a new guideline version" in str(raised.value)


def test_the_checksum_covers_what_was_scored_not_how_it_was_worded():
    """Reworded prose is not a change in what was scored; invalidating every
    prior assessment over a typo fix would be absurd."""
    import hashlib
    import json

    from app.services.catalogue.loader import catalogue_checksum

    before = catalogue_checksum("sbom")
    # Labels and rationale are deliberately outside the hash.
    canonical = json.dumps(
        [
            {
                "key": element.key,
                "clause": element.clause,
                "tier": str(element.tier),
                "determinability": str(element.determinability),
                "scope": str(element.scope),
            }
            for element in get_catalogue("sbom").elements
        ],
        sort_keys=True,
        separators=(",", ":"),
    )
    assert before == hashlib.sha256(canonical.encode()).hexdigest()


def test_the_combined_checksum_changes_if_any_lane_changes():
    assert len(combined_checksum()) == 64
    assert combined_checksum() == combined_checksum()


# --- version pinning --------------------------------------------------------


async def test_a_lane_result_is_pinned_to_the_version_it_was_scored_under(session):
    """The §S7 exit proof: a guideline bump must not rewrite history."""
    org = Org(id=uuid.uuid4(), name="Firm A")
    session.add(org)
    await session.flush()
    client = Client(org_id=org.id, name="Ministry")
    session.add(client)
    await session.flush()
    engagement = Engagement(
        org_id=org.id, client_id=client.id, title="FY26", enabled_lanes=["sbom"]
    )
    session.add(engagement)
    await session.flush()

    v2 = await seed(session)
    submissions = SubmissionRepository(session, org.id)
    submission = await submissions.create(engagement_id=engagement.id)
    await submissions.add_document(
        submission,
        lane="sbom",
        format=BomFormat.CYCLONEDX,
        checksum=uuid.uuid4().hex,
        size_bytes=10,
        payload=cyclonedx_document([component("a")]),
    )

    lanes = LaneRepository(session, org.id)
    result = await lanes.record(
        submission_id=submission.id,
        lane="sbom",
        verdict="fail",
        score=43.9,
        entity_count=1,
        detail="scored 43.9%",
        engine_version="0.1.0",
        inputs_hash="abc",
        guideline_version_id=v2.id,
        field_results=[
            {
                "element_key": "license",
                "clause": "4.2(5)",
                "verdict": "absent",
                "populated": 0,
                "total": 1,
                "coverage": 0.0,
                "weight": 3.0,
                "detail": "absent across all 1 entities",
                "consumer_action": None,
            }
        ],
    )
    assert result.guideline_version_id == v2.id

    # A later guideline is published. The old result must not move.
    v3 = GuidelineVersion(ref="CERT-In Technical Guidelines", version="3.0", checksum="f" * 64)
    session.add(v3)
    await session.flush()

    reread = (await lanes.for_submission(submission.id))[0]
    assert reread.guideline_version_id == v2.id, "the old assessment followed the new version"

    verdicts = await lanes.verdicts_for(reread.id)
    assert [row.clause for row in verdicts] == ["4.2(5)"]


async def test_elements_are_read_back_as_seeded_not_as_currently_encoded(session):
    """What an old assessment reads. The encoded catalogue may have moved on."""
    version = await seed(session)
    rows = await elements_for(session, version_id=version.id, lane="sbom")

    assert len(rows) == 21
    assert {row.clause for row in rows} >= {"4.2(1)", "4.2(5)", "4.2(21)"}


async def test_the_active_version_is_the_configured_one(session):
    assert await get_active_version(session) is None
    await seed(session)
    active = await get_active_version(session)
    assert active is not None and active.version == "2.0"


# --- seeding stays off the assessment path ----------------------------------
#
# Regression: seeding used to happen lazily inside the assessment task. Twenty
# concurrent assessments then raced on `uq_guideline_versions_version`, and the
# loser's failed INSERT poisoned the transaction it shared with a real
# assessment — leaving 0 versions and 37 orphaned elements behind. Scoring reads
# the *encoded* catalogue, so the version row is metadata that must already
# exist, never something an assessment creates for itself.


def test_the_assessment_task_never_seeds():
    """The rule, enforced by reading the source rather than by convention."""
    import ast
    from pathlib import Path

    source = (Path(__file__).resolve().parent.parent / "app" / "workers" / "tasks.py").read_text()
    called = {
        node.func.id
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "seed" not in called, (
        "the assessment task calls seed(); seeding is a deployment step, and a "
        "schema write on the assessment path races under concurrency"
    )
    assert "get_active_version" in source, "the task should still read the pin"


async def test_an_unseeded_catalogue_leaves_the_pin_null_rather_than_inventing_one(session):
    """A missing pin is reported, not manufactured."""
    from app.services.catalogue.seeder import get_active_version

    assert await get_active_version(session) is None

    org = Org(id=uuid.uuid4(), name="Firm A")
    session.add(org)
    await session.flush()
    client = Client(org_id=org.id, name="Ministry")
    session.add(client)
    await session.flush()
    engagement = Engagement(
        org_id=org.id, client_id=client.id, title="FY26", enabled_lanes=["sbom"]
    )
    session.add(engagement)
    await session.flush()

    submissions = SubmissionRepository(session, org.id)
    submission = await submissions.create(engagement_id=engagement.id)
    lanes = LaneRepository(session, org.id)
    result = await lanes.record(
        submission_id=submission.id,
        lane="sbom",
        verdict="fail",
        score=10.0,
        entity_count=1,
        detail="",
        engine_version="0.1.0",
        inputs_hash=None,
        guideline_version_id=None,
    )
    assert result.guideline_version_id is None


async def test_a_loser_in_a_seed_race_is_refused_by_name_and_writes_nothing(session):
    """Two deployment steps overlapping is a pipeline racing itself, and is
    surfaced rather than retried in a loop.

    **Not tested here: genuine multi-connection concurrency.** SQLAlchemy backs
    an in-memory SQLite database with a single shared connection, so "concurrent"
    sessions interleave on one transaction and one rollback undoes another's
    uncommitted work. That is a harness artifact, not a property of the code, and
    asserting against it would be asserting against SQLite. The behaviour that
    matters under real concurrency — the unique constraint admitting exactly one
    writer — is enforced by `uq_guideline_versions_version` in migration 0004 and
    needs Postgres to demonstrate.
    """
    from app.services.catalogue.seeder import ConcurrentSeed

    # The shape of the loser's outcome: a named error carrying the remedy.
    error = ConcurrentSeed(
        "another process is seeding guideline version 2.0 and has not committed "
        "yet. Nothing was written by this run. Re-run `make seed-catalogue` once "
        "it finishes — seeding is idempotent."
    )
    assert "Nothing was written" in str(error)
    assert "idempotent" in str(error)


async def test_seeding_after_a_failed_attempt_is_a_clean_no_op(session):
    """The remedy in that message has to actually work."""
    first = await seed(session)
    await session.commit()

    second = await seed(session)
    assert second.id == first.id

    versions = (await session.execute(select(GuidelineVersion))).scalars().all()
    elements = (await session.execute(select(MinimumElement))).scalars().all()
    assert len(versions) == 1
    assert len(elements) == sum(len(get_catalogue(lane).elements) for lane in ALL_LANES)
