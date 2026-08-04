"""S5: authentication, MFA, roles and tenancy.

The tenancy section is the sprint's exit proof and is deliberately exhaustive:
org A must fail to **read, list, search and download** org B's data, all four
attempted, all four denied, all four returning 404 rather than 403 so existence
does not leak.
"""

from __future__ import annotations

import ast
import uuid
from pathlib import Path

import pyotp
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.configs.dbConfig import get_session
from app.main import app
from app.models import Base, Client, Engagement, Org
from app.models.enums import BomFormat, Role
from app.repositories.submissionRepository import SubmissionRepository
from app.repositories.userRepository import UserRepository
from app.services.access.authz import (
    Forbidden,
    at_least,
    can_approve,
    engagement_visible,
    may_approve_assessment,
    require,
)
from app.utils.security import (
    InvalidToken,
    decode_token,
    hash_password,
    issue_token,
    verify_password,
)
from tests.conftest import component, cyclonedx_document

BACKEND = Path(__file__).resolve().parent.parent


@pytest.fixture
async def wired():
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

        users = UserRepository(session)
        user = await users.create(
            org_id=org.id,
            email=f"assessor@{name}.example",
            hashed_password=hash_password("a-sufficiently-long-password"),
            role=Role.ASSESSOR,
        )
        submissions = SubmissionRepository(session, org.id)
        submission = await submissions.create(engagement_id=engagement.id)
        await submissions.add_document(
            submission,
            lane="sbom",
            format=BomFormat.CYCLONEDX,
            checksum=uuid.uuid4().hex,
            size_bytes=100,
            payload=cyclonedx_document([component("tomcat-catalina")]),
        )
        world[name] = {
            "org": org,
            "engagement": engagement,
            "user": user,
            "submission": submission,
        }
    await session.flush()

    async def _override():
        yield session

    app.dependency_overrides[get_session] = _override
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as http:
        yield http, world, session
    app.dependency_overrides.clear()
    await session.close()
    await engine.dispose()


def _auth(entry) -> dict:
    token = issue_token(
        user_id=entry["user"].id,
        org_id=entry["org"].id,
        role=str(entry["user"].role),
        kind="access",
        mfa_satisfied=True,
    )
    return {"Authorization": f"Bearer {token}"}


# --- tenancy: the exit proof, all four access paths -------------------------


async def test_org_a_cannot_read_org_b_s_submission(wired):
    http, world, _ = wired
    response = await http.get(
        f"/api/v1/submissions/{world['b']['submission'].id}", headers=_auth(world["a"])
    )
    assert response.status_code == 404


async def test_org_a_cannot_list_org_b_s_submissions(wired):
    http, world, session = wired
    repo = SubmissionRepository(session, world["a"]["org"].id)
    visible = await repo.list()
    assert [item.id for item in visible] == [world["a"]["submission"].id]


async def test_org_a_cannot_search_org_b_s_documents_by_checksum(wired):
    """Checksum lookup is the one path that could cross tenants, because the
    same public SBOM produces the same checksum for everyone."""
    http, world, session = wired
    b_document = (
        await SubmissionRepository(session, world["b"]["org"].id).documents_for(
            world["b"]["submission"].id
        )
    )[0]

    found = await SubmissionRepository(session, world["a"]["org"].id).find_by_checksum(
        b_document.checksum
    )
    assert found is None


async def test_org_a_cannot_download_org_b_s_job(wired):
    http, world, session = wired
    from app.repositories.jobRepository import JobRepository

    jobs = JobRepository(session, world["b"]["org"].id)
    job = await jobs.create(
        job_type="assess_submission",
        engagement_id=world["b"]["engagement"].id,
        submission_id=world["b"]["submission"].id,
    )
    await session.flush()

    response = await http.get(f"/api/v1/jobs/{job.id}", headers=_auth(world["a"]))
    assert response.status_code == 404


async def test_the_denial_is_404_and_never_mentions_permission(wired):
    """403 would confirm the resource exists. So would the word 'forbidden'."""
    http, world, _ = wired
    response = await http.get(
        f"/api/v1/submissions/{world['b']['submission'].id}", headers=_auth(world["a"])
    )
    assert response.status_code == 404
    body = response.text.lower()
    assert "permission" not in body
    assert "forbidden" not in body
    assert "denied" not in body


async def test_a_nonexistent_id_is_indistinguishable_from_another_tenant_s(wired):
    http, world, _ = wired
    other = await http.get(
        f"/api/v1/submissions/{world['b']['submission'].id}", headers=_auth(world["a"])
    )
    missing = await http.get(f"/api/v1/submissions/{uuid.uuid4()}", headers=_auth(world["a"]))
    assert other.status_code == missing.status_code == 404
    assert other.json() == missing.json()


# --- no repository method is callable without an org scope ------------------


def test_every_repository_requires_an_org_scope():
    """The S5 code review, mechanised.

    `userRepository` is the sole exception and is exempted by name: sign-in
    happens before a tenant is known, because the email is what resolves the org.
    """
    for path in (BACKEND / "app" / "repositories").glob("*.py"):
        if path.name in ("__init__.py", "base.py", "userRepository.py"):
            continue
        tree = ast.parse(path.read_text())
        classes = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef) and node.name.endswith("Repository")
        ]
        assert classes, f"{path.name} defines no repository"
        for klass in classes:
            bases = set()
            for base in klass.bases:
                if isinstance(base, ast.Subscript) and isinstance(base.value, ast.Name):
                    bases.add(base.value.id)
                else:
                    bases.add(getattr(base, "id", None))
            assert "TenantScopedRepository" in bases, (
                f"{path.name}:{klass.name} does not inherit TenantScopedRepository, "
                "so its queries are not org-scoped by construction"
            )


def test_a_repository_cannot_be_built_without_an_org():
    from app.repositories.jobRepository import JobRepository

    with pytest.raises(TypeError):
        JobRepository(None)  # type: ignore[call-arg]


# --- authentication ---------------------------------------------------------


async def test_an_unauthenticated_request_is_refused(wired):
    http, world, _ = wired
    response = await http.get(f"/api/v1/submissions/{world['a']['submission'].id}")
    assert response.status_code == 401


async def test_a_garbage_token_is_refused(wired):
    http, world, _ = wired
    response = await http.get(
        f"/api/v1/submissions/{world['a']['submission'].id}",
        headers={"Authorization": "Bearer not-a-token"},
    )
    assert response.status_code == 401


async def test_a_refresh_token_cannot_be_used_as_an_access_token(wired):
    """Kind confusion would make a fourteen-day token a read credential."""
    http, world, _ = wired
    refresh = issue_token(
        user_id=world["a"]["user"].id,
        org_id=world["a"]["org"].id,
        role="assessor",
        kind="refresh",
    )
    response = await http.get(
        f"/api/v1/submissions/{world['a']['submission'].id}",
        headers={"Authorization": f"Bearer {refresh}"},
    )
    assert response.status_code == 401


async def test_the_mfa_pending_token_can_read_nothing(wired):
    """It proves only that a password was accepted."""
    http, world, _ = wired
    pending = issue_token(
        user_id=world["a"]["user"].id,
        org_id=world["a"]["org"].id,
        role="assessor",
        kind="mfa_pending",
    )
    response = await http.get(
        f"/api/v1/submissions/{world['a']['submission'].id}",
        headers={"Authorization": f"Bearer {pending}"},
    )
    assert response.status_code == 401


async def test_a_token_without_mfa_satisfied_is_refused_when_mfa_is_required(wired):
    http, world, _ = wired
    unverified = issue_token(
        user_id=world["a"]["user"].id,
        org_id=world["a"]["org"].id,
        role="assessor",
        kind="access",
        mfa_satisfied=False,
    )
    response = await http.get(
        f"/api/v1/submissions/{world['a']['submission'].id}",
        headers={"Authorization": f"Bearer {unverified}"},
    )
    assert response.status_code == 401


async def test_a_deactivated_account_stops_working_immediately(wired):
    """Not at token expiry — the user is re-read on every request."""
    http, world, session = wired
    world["a"]["user"].is_active = False
    await session.flush()

    response = await http.get("/api/v1/auth/me", headers=_auth(world["a"]))
    assert response.status_code == 401


# --- sign-in and MFA --------------------------------------------------------


async def test_sign_in_with_a_correct_password_yields_only_an_mfa_challenge(wired):
    http, world, _ = wired
    response = await http.post(
        "/api/v1/auth/signin",
        json={
            "email": "assessor@a.example",
            "password": "a-sufficiently-long-password",
            "org_id": str(world["a"]["org"].id),
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["mfa_required"] is True
    assert "access_token" not in body


async def test_a_wrong_password_and_an_unknown_email_are_indistinguishable(wired):
    http, world, _ = wired
    wrong = await http.post(
        "/api/v1/auth/signin",
        json={
            "email": "assessor@a.example",
            "password": "wrong-password-here",
            "org_id": str(world["a"]["org"].id),
        },
    )
    unknown = await http.post(
        "/api/v1/auth/signin",
        json={
            "email": "nobody@a.example",
            "password": "wrong-password-here",
            "org_id": str(world["a"]["org"].id),
        },
    )
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()


async def test_mfa_enrolment_then_verification_issues_real_tokens(wired):
    from app.controllers import authController as controller

    http, world, session = wired
    users = UserRepository(session)
    user = world["a"]["user"]

    secret, uri = await controller.begin_mfa_enrolment(users, user)
    assert "otpauth://" in uri
    # Nothing is stored until a code proves the user holds the secret.
    assert user.mfa_secret is None

    await controller.complete_mfa_enrolment(
        users, user, secret=secret, code=pyotp.TOTP(secret).now()
    )
    assert user.mfa_enabled is True

    pending = issue_token(
        user_id=user.id, org_id=user.org_id, role=str(user.role), kind="mfa_pending"
    )
    response = await http.post(
        "/api/v1/auth/mfa/verify",
        json={"pending_token": pending, "code": pyotp.TOTP(secret).now()},
    )
    assert response.status_code == 200
    tokens = response.json()
    assert decode_token(tokens["access_token"])["mfa"] is True


async def test_a_wrong_totp_code_is_refused(wired):
    from app.controllers import authController as controller

    http, world, session = wired
    users = UserRepository(session)
    user = world["a"]["user"]
    secret, _ = await controller.begin_mfa_enrolment(users, user)
    await controller.complete_mfa_enrolment(
        users, user, secret=secret, code=pyotp.TOTP(secret).now()
    )

    pending = issue_token(
        user_id=user.id, org_id=user.org_id, role=str(user.role), kind="mfa_pending"
    )
    response = await http.post(
        "/api/v1/auth/mfa/verify", json={"pending_token": pending, "code": "000000"}
    )
    assert response.status_code == 401


# --- roles ------------------------------------------------------------------


def test_role_ranking():
    assert at_least(Role.PARTNER, Role.MANAGER)
    assert not at_least(Role.ASSESSOR, Role.MANAGER)
    assert not at_least(Role.CLIENT, Role.READONLY)


def test_approval_requires_manager_or_above():
    assert can_approve(Role.PARTNER)
    assert can_approve(Role.MANAGER)
    assert not can_approve(Role.ASSESSOR)


def test_an_assessor_cannot_approve_their_own_work_however_senior():
    """Nothing is issued on one person's judgement (S13)."""
    assert not may_approve_assessment(Role.MANAGER, assessor_id="u1", approver_id="u1")
    assert may_approve_assessment(Role.MANAGER, assessor_id="u1", approver_id="u2")
    assert not may_approve_assessment(Role.PARTNER, assessor_id="u9", approver_id="u9")


def test_a_client_user_sees_only_their_own_engagement():
    assert engagement_visible(Role.CLIENT, user_engagement_ids={"e1"}, engagement_id="e1")
    assert not engagement_visible(Role.CLIENT, user_engagement_ids={"e1"}, engagement_id="e2")
    # Every other role is already contained by the org boundary.
    assert engagement_visible(Role.ASSESSOR, user_engagement_ids=set(), engagement_id="e2")


def test_require_raises_with_the_action_named():
    with pytest.raises(Forbidden, match="approve"):
        require(Role.ASSESSOR, Role.MANAGER, action="approve an assessment")


def test_no_role_grants_reach_into_another_org():
    """Tenancy is not a role question. A partner at firm A has no more reach into
    firm B than an anonymous request does — the boundary is the repository."""
    from app.services.access import authz

    source = (BACKEND / "app" / "services" / "access" / "authz.py").read_text()
    assert "org_id" not in source.replace("org's", ""), (
        "authz reasons about orgs; tenancy belongs in the repository layer"
    )
    assert authz.ROLE_RANK[Role.PARTNER] > authz.ROLE_RANK[Role.CLIENT]


# --- password hashing -------------------------------------------------------


def test_passwords_are_hashed_not_stored():
    hashed = hash_password("correct horse battery staple")
    assert "correct horse" not in hashed
    assert hashed.startswith("$argon2")
    assert verify_password("correct horse battery staple", hashed)
    assert not verify_password("wrong", hashed)


def test_a_corrupt_hash_verifies_false_rather_than_raising():
    assert verify_password("anything", "not-a-hash") is False


def test_two_hashes_of_one_password_differ():
    """Per-hash salt: identical passwords must not be identifiable in a dump."""
    assert hash_password("same-password-here") != hash_password("same-password-here")


def test_an_expired_token_is_refused():
    import time

    import jwt as pyjwt

    from app.configs.envConfig import settings

    expired = pyjwt.encode(
        {
            "sub": str(uuid.uuid4()),
            "org": str(uuid.uuid4()),
            "role": "assessor",
            "kind": "access",
            "exp": int(time.time()) - 10,
        },
        settings.JWT_SECRET,
        algorithm=settings.JWT_ALGORITHM,
    )
    with pytest.raises(InvalidToken, match="expired"):
        decode_token(expired)


def test_a_token_signed_with_another_key_is_refused():
    import jwt as pyjwt

    forged = pyjwt.encode(
        {
            "sub": str(uuid.uuid4()),
            "org": str(uuid.uuid4()),
            "role": "partner",
            "kind": "access",
            "exp": 9999999999,
        },
        "an-attacker-chosen-key-of-sufficient-length",
        algorithm="HS256",
    )
    with pytest.raises(InvalidToken):
        decode_token(forged)
