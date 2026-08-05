"""S21: an exhausted quota is a 429 handled as a real UI state, never a 500.

The exit condition is about the *shape of the answer*. A 500 says we broke. A bare
429 says stop, without saying what bound, for how long, or what to do — and a
console given that has nothing to render but a toast. So every refusal here is
asserted to carry the quota, the limit, the usage, the reset and a remedy, and to
arrive as a 429 even when it is raised from somewhere the route did not expect.

The last part is the one that actually protects the exit condition: the handler is
registered on the app, so a `QuotaExceeded` from any service becomes a 429. Left
to individual routes, the first one that forgot would return a 500, which is the
failure this condition names.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.configs.dbConfig import get_session
from app.configs.jobTypes import JobType
from app.main import app
from app.models import Base, Client, Engagement, Org
from app.models.enums import Role
from app.repositories.jobRepository import JobRepository
from app.repositories.submissionRepository import SubmissionRepository
from app.repositories.userRepository import UserRepository
from app.services.quota.plans import PLAN_LIMITS, Plan, Quota, limits_for
from app.services.quota.service import (
    QuotaExceeded,
    QuotaService,
    RateLimiter,
    declared_entry_count,
    limiter,
    month_start,
    next_month_start,
)
from app.utils.security import hash_password, issue_token
from tests.conftest import component, cyclonedx_document


@pytest.fixture(autouse=True)
def _fresh_limiter():
    """A shared limiter would make these tests order-dependent."""
    limiter.reset()
    yield
    limiter.reset()


@pytest.fixture
async def wired():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    session = async_sessionmaker(engine, expire_on_commit=False)()

    org = Org(id=uuid.uuid4(), name="Firm A", plan=str(Plan.STARTER))
    session.add(org)
    await session.flush()
    client = Client(org_id=org.id, name="Client A")
    session.add(client)
    await session.flush()
    engagement = Engagement(
        org_id=org.id, client_id=client.id, title="E", enabled_lanes=["sbom"]
    )
    session.add(engagement)
    await session.flush()
    user = await UserRepository(session).create(
        org_id=org.id,
        email="assessor@a.example",
        hashed_password=hash_password("a-sufficiently-long-password"),
        role=Role.ASSESSOR,
    )
    await session.commit()

    async def _override():
        yield session

    app.dependency_overrides[get_session] = _override
    token = issue_token(
        user_id=user.id, org_id=org.id, role=str(user.role), kind="access", mfa_satisfied=True
    )
    headers = {"Authorization": f"Bearer {token}"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as http:
        yield http, headers, session, org, engagement
    app.dependency_overrides.clear()
    await session.close()
    await engine.dispose()


def _body(engagement_id, entries: int = 1) -> dict:
    return {
        "engagement_id": str(engagement_id),
        "documents": [
            {
                "lane": "sbom",
                "format": "CycloneDX",
                "payload": cyclonedx_document(
                    [component(f"pkg-{index}", "1.0.0") for index in range(entries)]
                ),
            }
        ],
    }


# --- the plan table ----------------------------------------------------------


def test_unlimited_is_none_rather_than_a_large_number():
    """A sentinel like 999_999 eventually gets compared, logged and displayed, and
    then somebody has to explain a limit that does not exist."""
    enterprise = PLAN_LIMITS[Plan.ENTERPRISE]
    assert enterprise.submissions_per_month is None
    assert enterprise.components_per_submission is None
    assert enterprise.requests_per_minute is None


def test_an_unrecognised_plan_gets_the_most_restrictive_limits():
    """A typo in a plan column must not silently grant unlimited service. The
    failure should be a 429 the client can query, not a bill we discover later."""
    assert limits_for("premium-gold-tier") == PLAN_LIMITS[Plan.STARTER]
    assert limits_for("") == PLAN_LIMITS[Plan.STARTER]


def test_every_plan_decides_every_quota():
    for plan, limits in PLAN_LIMITS.items():
        for quota in Quota:
            value = limits.of(quota)
            assert value is None or value > 0, f"{plan}.{quota} is {value}"


def test_generation_is_metered_far_more_tightly_than_submission():
    """It resolves dependencies in a sandbox and takes minutes rather than
    seconds (S17), so the two cannot share an allowance."""
    for plan, limits in PLAN_LIMITS.items():
        if limits.submissions_per_month is None:
            continue
        assert limits.repo_generations_per_month is not None
        assert limits.repo_generations_per_month < limits.submissions_per_month, plan


# --- the submission quota, end to end ---------------------------------------


async def test_an_exhausted_submission_quota_returns_429_not_500(wired):
    """The §S21 exit proof."""
    http, headers, session, org, engagement = wired
    submissions = SubmissionRepository(session, org.id)
    for _ in range(PLAN_LIMITS[Plan.STARTER].submissions_per_month or 0):
        await submissions.create(engagement_id=engagement.id)
    await session.commit()

    response = await http.post("/api/v1/submissions", json=_body(engagement.id), headers=headers)

    assert response.status_code == 429


async def test_the_429_body_is_a_ui_state_rather_than_a_message(wired):
    """Enough for the console to render a screen and for support to start from
    fact: what bound, the limit, the usage, when it lifts, and what to do."""
    http, headers, session, org, engagement = wired
    submissions = SubmissionRepository(session, org.id)
    for _ in range(25):
        await submissions.create(engagement_id=engagement.id)
    await session.commit()

    response = await http.post("/api/v1/submissions", json=_body(engagement.id), headers=headers)
    body = response.json()

    assert body["quota"] == "submissions_per_month"
    assert body["limit"] == 25
    assert body["used"] == 25
    assert body["plan"] == "starter"
    assert body["resets_at"]
    assert body["remedy"]
    assert response.headers["Retry-After"]


async def test_the_retry_after_header_points_at_the_reset(wired):
    http, headers, session, org, engagement = wired
    submissions = SubmissionRepository(session, org.id)
    for _ in range(25):
        await submissions.create(engagement_id=engagement.id)
    await session.commit()

    response = await http.post("/api/v1/submissions", json=_body(engagement.id), headers=headers)
    seconds = int(response.headers["Retry-After"])
    expected = (next_month_start() - datetime.now(UTC)).total_seconds()

    assert abs(seconds - expected) < 60


async def test_a_submission_under_the_quota_is_created_normally(wired):
    http, headers, _, _, engagement = wired
    response = await http.post("/api/v1/submissions", json=_body(engagement.id), headers=headers)
    assert response.status_code == 201


async def test_the_quota_is_checked_before_the_documents_are_stored(wired):
    """Refusing after the upload has been parsed would charge us for the work and
    still tell the client no."""
    http, headers, session, org, engagement = wired
    submissions = SubmissionRepository(session, org.id)
    for _ in range(25):
        await submissions.create(engagement_id=engagement.id)
    await session.commit()
    before = await submissions.count()

    await http.post("/api/v1/submissions", json=_body(engagement.id), headers=headers)

    assert await submissions.count() == before


async def test_usage_from_a_previous_month_does_not_count_against_this_one(wired):
    """A monthly allowance that never resets is not a monthly allowance."""
    http, headers, session, org, engagement = wired
    submissions = SubmissionRepository(session, org.id)
    last_month = month_start() - timedelta(days=5)
    for _ in range(25):
        created = await submissions.create(engagement_id=engagement.id)
        created.created_at = last_month
    await session.commit()

    response = await http.post("/api/v1/submissions", json=_body(engagement.id), headers=headers)
    assert response.status_code == 201


# --- the component quota -----------------------------------------------------


async def test_a_document_over_the_component_limit_is_refused_not_truncated(wired):
    """Scoring the first 5,000 components of a 40,000-component estate would
    produce a figure that looks complete and describes an eighth of the software —
    the partial-coverage failure §11 forbids, arriving through billing."""
    http, headers, session, org, engagement = wired
    quotas = QuotaService(session, org.id)

    with pytest.raises(QuotaExceeded) as raised:
        await quotas.check_components(5_001)

    assert raised.value.quota is Quota.COMPONENTS
    assert "refused rather than truncated" in raised.value.remedy


async def test_the_component_refusal_offers_no_retry_because_nothing_resets(wired):
    http, headers, session, org, engagement = wired
    quotas = QuotaService(session, org.id)

    with pytest.raises(QuotaExceeded) as raised:
        await quotas.check_components(10_000)

    assert raised.value.retry_after == 0
    assert raised.value.resets_at is None
    assert "Split the submission or change plan" in raised.value.remedy


async def test_a_component_overage_arrives_as_429_through_the_api(wired):
    http, headers, session, org, engagement = wired
    response = await http.post(
        "/api/v1/submissions", json=_body(engagement.id, entries=5_001), headers=headers
    )

    assert response.status_code == 429
    assert response.json()["quota"] == "components_per_submission"
    # No Retry-After: waiting will not help, and sending one would invite a
    # client to retry the same document in a month.
    assert "Retry-After" not in response.headers


def test_entries_are_counted_across_both_serialisations():
    """CycloneDX says `components`, SPDX says `packages`; the quota is about
    volume rather than vocabulary."""
    assert declared_entry_count({"components": [1, 2], "packages": [3]}) == 3
    assert declared_entry_count({"bomFormat": "CycloneDX"}) == 0


# --- the generation quota ----------------------------------------------------


async def test_repo_generation_is_metered_separately_from_submissions(wired):
    """Uploading a BOM your own build produced must not consume the generation
    allowance, and vice versa."""
    http, headers, session, org, engagement = wired
    jobs = JobRepository(session, org.id)
    for _ in range(5):
        await jobs.create(
            job_type=JobType.GENERATE_FROM_REPO, engagement_id=engagement.id
        )
    await session.commit()

    quotas = QuotaService(session, org.id)
    with pytest.raises(QuotaExceeded) as raised:
        await quotas.check_repo_generation()
    assert raised.value.quota is Quota.REPO_GENERATIONS

    # Submissions are untouched by five generations.
    await quotas.check_submission()


async def test_assessment_jobs_do_not_count_against_the_generation_quota(wired):
    http, headers, session, org, engagement = wired
    jobs = JobRepository(session, org.id)
    for _ in range(20):
        await jobs.create(
            job_type=JobType.ASSESS_SUBMISSION, engagement_id=engagement.id
        )
    await session.commit()

    await QuotaService(session, org.id).check_repo_generation()


# --- rate limiting -----------------------------------------------------------


def test_the_rate_limiter_refuses_past_the_window_limit():
    bucket = RateLimiter()
    for _ in range(3):
        bucket.check("org:a", limit=3, plan="starter")

    with pytest.raises(QuotaExceeded) as raised:
        bucket.check("org:a", limit=3, plan="starter")
    assert raised.value.quota is Quota.REQUESTS
    assert raised.value.retry_after > 0


def test_the_window_slides_rather_than_resetting_on_a_fixed_boundary():
    """A fixed boundary lets a client send 2× the limit across the tick."""
    bucket = RateLimiter()
    for _ in range(3):
        bucket.check("org:a", limit=3, plan="starter", window=0.0)

    bucket.check("org:a", limit=3, plan="starter", window=0.0)


def test_one_tenant_cannot_exhaust_another_tenants_rate_limit():
    bucket = RateLimiter()
    for _ in range(3):
        bucket.check("org:a", limit=3, plan="starter")

    bucket.check("org:b", limit=3, plan="starter")


def test_an_unlimited_plan_is_not_rate_limited():
    bucket = RateLimiter()
    for _ in range(1_000):
        bucket.check("org:a", limit=None, plan="enterprise")


async def test_the_rate_limit_arrives_as_429_through_the_api(wired):
    http, headers, _, _, _ = wired

    statuses = set()
    for _ in range(130):
        statuses.add((await http.get("/api/v1/submissions", headers=headers)).status_code)

    assert 429 in statuses
    assert 500 not in statuses


# --- the usage endpoint ------------------------------------------------------


async def test_a_client_can_read_its_usage_before_hitting_a_limit(wired):
    """A limit a client discovers by hitting it is a support ticket."""
    http, headers, session, org, engagement = wired
    submissions = SubmissionRepository(session, org.id)
    for _ in range(3):
        await submissions.create(engagement_id=engagement.id)
    await session.commit()

    report = (await http.get("/api/v1/submissions/usage", headers=headers)).json()

    assert report["plan"] == "starter"
    quotas = {row["quota"]: row for row in report["quotas"]}
    assert quotas["submissions_per_month"]["used"] == 3
    assert quotas["submissions_per_month"]["remaining"] == 22
    assert quotas["submissions_per_month"]["unlimited"] is False


async def test_usage_never_reports_a_negative_remainder(wired):
    """Overage happens — a plan downgrade mid-month is enough. "-3 remaining" is
    not a state a UI can render."""
    http, headers, session, org, engagement = wired
    submissions = SubmissionRepository(session, org.id)
    for _ in range(30):
        await submissions.create(engagement_id=engagement.id)
    await session.commit()

    report = (await http.get("/api/v1/submissions/usage", headers=headers)).json()
    quotas = {row["quota"]: row for row in report["quotas"]}
    assert quotas["submissions_per_month"]["remaining"] == 0
    assert quotas["submissions_per_month"]["used"] == 30


async def test_usage_is_scoped_to_the_tenant(wired):
    """A quota query reaching across tenants is a slow leak of one client's volume
    into another's bill."""
    http, headers, session, org, engagement = wired
    other = Org(id=uuid.uuid4(), name="Firm B", plan=str(Plan.STARTER))
    session.add(other)
    await session.flush()
    other_client = Client(org_id=other.id, name="Client B")
    session.add(other_client)
    await session.flush()
    other_engagement = Engagement(
        org_id=other.id, client_id=other_client.id, title="EB", enabled_lanes=["sbom"]
    )
    session.add(other_engagement)
    await session.flush()
    for _ in range(10):
        await SubmissionRepository(session, other.id).create(
            engagement_id=other_engagement.id
        )
    await session.commit()

    report = (await http.get("/api/v1/submissions/usage", headers=headers)).json()
    quotas = {row["quota"]: row for row in report["quotas"]}
    assert quotas["submissions_per_month"]["used"] == 0


# --- the handler is what makes 500 impossible -------------------------------


def test_the_app_handles_quota_exceeded_so_no_route_can_leak_a_500():
    """Registered on the app rather than per route. The first route that forgot
    would return a 500, which is exactly the failure this condition names."""
    assert QuotaExceeded in app.exception_handlers


async def test_a_quota_raised_from_an_unexpected_place_is_still_a_429(wired):
    """Simulates a service deep in a read path raising the exception — a route
    that never mentions quotas at all."""
    http, headers, session, org, engagement = wired
    from app.controllers import submissionController

    async def _boom(*args, **kwargs):
        raise QuotaExceeded(
            quota=Quota.SUBMISSIONS,
            limit=25,
            used=25,
            plan="starter",
            resets_at=next_month_start(),
            retry_after=60,
            remedy="wait",
        )

    original = submissionController.list_submissions
    submissionController.list_submissions = _boom  # type: ignore[assignment]
    try:
        response = await http.get("/api/v1/submissions", headers=headers)
    finally:
        submissionController.list_submissions = original  # type: ignore[assignment]

    assert response.status_code == 429
    assert response.json()["quota"] == "submissions_per_month"
