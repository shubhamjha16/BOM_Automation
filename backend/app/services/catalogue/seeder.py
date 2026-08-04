"""Seed the encoded catalogue into `minimum_elements`, pinned to a version row.

**Seeding is a deployment step, not a request-path step** — it belongs beside
`alembic upgrade head`, and for the same reason. An earlier version of this
module seeded lazily from inside the assessment task; twenty concurrent
assessments then raced, and the loser's failed INSERT poisoned the transaction it
was sharing with a real assessment. Scoring does not need the table — it reads
the encoded catalogue — so the version row is metadata that must already exist,
never something an assessment creates for itself.

**Seeding is idempotent and version-scoped, not upsert-in-place.** Re-running it
for an existing version is a no-op; a *changed* catalogue for an existing version
is an error, not an update. That distinction is the whole point of the table:

* If v2.0's elements could be edited in place, every assessment already scored
  under v2.0 would silently start reporting against something else. A client
  holding an assessment could not say what it was measured against.
* So a catalogue change means a new `guideline_versions` row, and old lane
  results keep pointing at the old one.

The checksum is what detects the difference. It covers clause, tier,
determinability and scope — what was scored — and deliberately not labels or
rationale, since reworded prose does not change a verdict and invalidating every
prior assessment over a typo fix would be absurd.
"""

from __future__ import annotations

from datetime import date

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.configs.envConfig import ALL_LANES, settings
from app.models.enums import Determinability, Tier
from app.models.guideline import GuidelineVersion, MinimumElement
from app.services.catalogue.loader import catalogue_checksum, get_catalogue, guideline_ref
from app.utils.logger import get_logger

logger = get_logger(__name__)


class CatalogueDrift(RuntimeError):
    """The encoded catalogue no longer matches the seeded version of the same name."""


class ConcurrentSeed(RuntimeError):
    """Another seeding run won the race and has not committed yet.

    Only reachable when two deployment steps overlap, which they should not.
    Raised rather than retried in a loop: seeding is idempotent, so the fix is to
    run it again once the other has finished, and a silent retry here would hide
    a deployment pipeline that is racing itself.
    """


def combined_checksum() -> str:
    """One checksum across every lane, in a fixed lane order."""
    import hashlib

    material = "|".join(f"{lane}:{catalogue_checksum(lane)}" for lane in ALL_LANES)
    return hashlib.sha256(material.encode()).hexdigest()


async def get_active_version(session: AsyncSession) -> GuidelineVersion | None:
    """The version row matching the configured `GUIDELINE_VERSION`."""
    result = await session.execute(
        select(GuidelineVersion).where(GuidelineVersion.version == settings.GUIDELINE_VERSION)
    )
    return result.scalar_one_or_none()


async def seed(session: AsyncSession, *, reviewed_by: str | None = None) -> GuidelineVersion:
    """Seed, or confirm the seeded catalogue still matches the encoded one.

    Owns its transaction. Call it from deployment or from worker startup — not
    from a request or a task, which would put a schema write on the assessment
    path.
    """
    checksum = combined_checksum()
    existing = await get_active_version(session)

    if existing is not None:
        if existing.checksum != checksum:
            raise CatalogueDrift(
                f"guideline version {settings.GUIDELINE_VERSION} is already seeded with "
                f"checksum {existing.checksum[:12]}, but the encoded catalogue now "
                f"hashes to {checksum[:12]}. The minimum elements were edited without "
                "a version bump. Assessments already scored under this version would "
                "silently start reporting against different rules — publish a new "
                "guideline version instead of editing this one."
            )
        logger.info("catalogue_already_seeded", version=existing.version)
        return existing

    reference = guideline_ref()
    published = None
    try:
        published = date.fromisoformat(reference["published_on"])
    except (ValueError, KeyError):  # pragma: no cover - config is validated
        published = None

    version = GuidelineVersion(
        ref=reference["ref"],
        version=reference["version"],
        published_on=published,
        checksum=checksum,
        reviewed_by=reviewed_by,
    )
    session.add(version)
    try:
        await session.flush()
    except IntegrityError:
        # Two deployment steps ran at once. `uq_guideline_versions_version` lets
        # exactly one win; the loser rolls its own transaction back and re-reads
        # rather than leaving a half-seeded catalogue behind.
        await session.rollback()
        winner = await get_active_version(session)
        if winner is None:
            # The constraint fired, so a row exists — but the writer has not
            # committed, so this transaction cannot see it. Nothing was
            # half-written: the rollback above took the elements with it.
            raise ConcurrentSeed(
                f"another process is seeding guideline version "
                f"{settings.GUIDELINE_VERSION} and has not committed yet. Nothing "
                "was written by this run. Re-run `make seed-catalogue` once it "
                "finishes — seeding is idempotent."
            ) from None
        logger.info("catalogue_seed_race_lost", version=winner.version)
        if winner.checksum != checksum:
            raise CatalogueDrift(
                f"guideline version {settings.GUIDELINE_VERSION} was seeded concurrently "
                f"with a different checksum ({winner.checksum[:12]} vs {checksum[:12]})"
            ) from None
        return winner

    seeded = 0
    for lane in ALL_LANES:
        for element in get_catalogue(lane).elements:
            session.add(
                MinimumElement(
                    guideline_version_id=version.id,
                    lane=lane,
                    key=element.key,
                    label=element.label,
                    clause=element.clause,
                    tier=Tier(str(element.tier)),
                    determinability=Determinability(str(element.determinability)),
                    scope=str(element.scope),
                    rationale=element.rationale or None,
                    consumer_action=element.consumer_action or None,
                )
            )
            seeded += 1
    await session.flush()

    logger.info(
        "catalogue_seeded",
        version=version.version,
        elements=seeded,
        checksum=checksum[:12],
    )
    return version


async def elements_for(
    session: AsyncSession, *, version_id: str, lane: str
) -> list[MinimumElement]:
    """Read a lane's elements as they were seeded, not as they are encoded now.

    This is what an old assessment reads. The encoded catalogue may have moved on;
    the assessment must not.
    """
    result = await session.execute(
        select(MinimumElement)
        .where(MinimumElement.guideline_version_id == version_id)
        .where(MinimumElement.lane == lane)
        .order_by(MinimumElement.clause)
    )
    return list(result.scalars().all())
