"""S20: the authorization matrix, and the audited cross-org retrieval.

Two things live here, and they answer different questions.

The **matrix** answers "within your own tenant, may you do this?" — asserted as a
complete table rather than as spot checks, so that adding a resource forces a
decision about who may reach it instead of inheriting whatever the first endpoint
allowed.

The **cross-org probe** answers the tenancy question, which no role can grant.
Its exit condition is peculiar and worth stating plainly: the attempt must return
nothing *and* raise an audit event. The caller is told nothing — a 404
indistinguishable from a genuine miss — so the audit row is the only record that
the attempt happened at all.
"""

from __future__ import annotations

import ast
import uuid
from itertools import product
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.models import Base, Client, Engagement, Org
from app.models.auditEvent import AuditEvent
from app.models.enums import BomFormat, Role
from app.repositories.submissionRepository import SubmissionRepository
from app.services.access.audit import CROSS_TENANT_DENIED
from app.services.access.authz import can_approve, can_submit, is_read_only
from app.services.access.matrix import (
    MATRIX,
    Action,
    Resource,
    as_table,
    may,
    missing_cells,
)
from tests.conftest import component, cyclonedx_document

BACKEND = Path(__file__).resolve().parent.parent


# --- the matrix is complete -------------------------------------------------


def test_every_role_resource_pair_is_decided():
    """The exit condition. A missing cell is not "denied by accident" — it is a
    resource somebody shipped without deciding who may reach it."""
    assert missing_cells() == []
    assert len(as_table()) == len(list(Role)) * len(list(Resource))


@pytest.mark.parametrize(("role", "resource"), list(product(Role, Resource)))
def test_each_cell_names_only_real_actions(role, resource):
    assert MATRIX[role][resource] <= frozenset(Action)


def test_the_matrix_is_closed_so_an_unknown_pairing_is_denied():
    """`may()` must never raise and must never default to permit."""

    class Ghost:
        pass

    assert may(Role.PARTNER, Ghost(), Action.READ) is False  # type: ignore[arg-type]
    assert may(Ghost(), Resource.SUBMISSION, Action.READ) is False  # type: ignore[arg-type]


# --- the decisions that matter ----------------------------------------------


def test_no_role_below_manager_may_approve_an_assessment():
    """The review gate (S13) as a matrix property rather than one endpoint's
    check: an assessor may create, edit and export an assessment and may never
    approve one."""
    for role in (Role.ASSESSOR, Role.READONLY, Role.CLIENT):
        assert not may(role, Resource.ASSESSMENT, Action.APPROVE)
    for role in (Role.MANAGER, Role.PARTNER):
        assert may(role, Resource.ASSESSMENT, Action.APPROVE)


def test_an_assessor_may_still_run_the_assessment_they_cannot_approve():
    assert may(Role.ASSESSOR, Resource.ASSESSMENT, Action.CREATE)
    assert may(Role.ASSESSOR, Resource.ASSESSMENT, Action.UPDATE)


def test_a_client_cannot_read_the_firms_curated_assets():
    """The supplier registry and the identifier mappings are the firm's work
    product across every client. A client sitting inside the right org must not
    read them, which is why tenancy alone is not the whole answer."""
    assert not may(Role.CLIENT, Resource.SUPPLIER_REGISTRY, Action.READ)
    assert not may(Role.CLIENT, Resource.IDENTIFIER_MAPPING, Action.READ)
    assert not may(Role.CLIENT, Resource.REPOSITORY, Action.READ)


def test_a_client_may_read_and_export_their_own_assessment():
    assert may(Role.CLIENT, Resource.ASSESSMENT, Action.READ)
    assert may(Role.CLIENT, Resource.ASSESSMENT, Action.EXPORT)


def test_only_a_partner_may_delete():
    """Deletion is the one action with no undo, so it sits at one role."""
    deleters = {
        role
        for role, resource, action in product(Role, Resource, [Action.DELETE])
        if may(role, resource, action)
    }
    assert deleters == {Role.PARTNER}


def test_no_role_may_write_the_audit_trail():
    """An audit trail an application can edit is not an audit trail. Rows are
    written by `services/access/audit.py`, never through a permission."""
    for role, action in product(Role, [Action.CREATE, Action.UPDATE, Action.DELETE]):
        assert not may(role, Resource.AUDIT_EVENT, action)


def test_only_partners_and_managers_read_the_audit_trail():
    for role in (Role.PARTNER, Role.MANAGER):
        assert may(role, Resource.AUDIT_EVENT, Action.READ)
    for role in (Role.ASSESSOR, Role.READONLY, Role.CLIENT):
        assert not may(role, Resource.AUDIT_EVENT, Action.READ)


def test_read_and_list_travel_together():
    """A role that may read one row may enumerate the collection it scopes to.

    Splitting them produces an oracle: denied listing plus permitted reads lets a
    caller enumerate by id, learning what exists from the difference between the
    two answers. Listing leaks nothing the reads did not, because the repository
    layer scopes the list to the same rows.

    This caught two cells on the client role, where read-without-list looked like
    caution and was only inconsistency.
    """
    for role, resource in product(Role, Resource):
        actions = MATRIX[role][resource]
        if Action.READ in actions:
            assert Action.LIST in actions, f"{role} may read but not list {resource}"


def test_no_role_may_update_what_it_cannot_read():
    for role, resource in product(Role, Resource):
        actions = MATRIX[role][resource]
        if Action.UPDATE in actions or Action.DELETE in actions:
            assert Action.READ in actions, f"{role} may write {resource} blind"


# --- the predicates are derived, not restated -------------------------------


@pytest.mark.parametrize("role", list(Role))
def test_the_role_predicates_agree_with_the_matrix(role):
    """Two hand-maintained lists drift silently. These read the table."""
    assert can_submit(role) is may(role, Resource.SUBMISSION, Action.CREATE)
    assert can_approve(role) is may(role, Resource.ASSESSMENT, Action.APPROVE)
    assert is_read_only(role) is not can_submit(role)


def test_the_client_role_is_read_only_as_s16_specifies():
    """This is the inconsistency the matrix caught: `can_submit` admitted a
    client while `is_read_only` also called that role read-only, and nothing
    forced the two to agree because neither was called anywhere."""
    assert is_read_only(Role.CLIENT)
    assert not can_submit(Role.CLIENT)


def test_authz_holds_no_second_copy_of_the_role_lists():
    """A literal role tuple in a predicate is the drift this sprint removed."""
    source = (BACKEND / "app" / "services" / "access" / "authz.py").read_text()
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef) or node.name in (
            "engagement_visible",
            "engagement_scope_for",
        ):
            continue
        for inner in ast.walk(node):
            if isinstance(inner, (ast.Tuple, ast.Set, ast.List)) and len(inner.elts) > 1:
                pytest.fail(f"{node.name} restates a role list instead of reading the matrix")


# --- the cross-org retrieval, and the audit row that is its only trace -------


@pytest.fixture
async def two_orgs():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)

    # `record_out_of_band` opens its own session, deliberately, so the audit row
    # survives the rollback that a denial causes. It must therefore reach *this*
    # database rather than the configured one.
    import app.configs.dbConfig as db_config

    original = db_config.get_sessionmaker
    db_config.get_sessionmaker = lambda: sessionmaker  # type: ignore[assignment]

    session = sessionmaker()
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
        world[name] = {"org": org, "submission": submission, "engagement": engagement}
    await session.commit()

    yield session, world, sessionmaker

    db_config.get_sessionmaker = original  # type: ignore[assignment]
    await session.close()
    await engine.dispose()


async def _audit_rows(sessionmaker) -> list[AuditEvent]:
    async with sessionmaker() as reader:
        result = await reader.execute(
            select(AuditEvent).where(AuditEvent.action == CROSS_TENANT_DENIED)
        )
        return list(result.scalars().all())


async def test_a_crafted_cross_org_retrieval_returns_nothing(two_orgs):
    """The §S20 exit proof, first half."""
    session, world, _ = two_orgs
    repository = SubmissionRepository(session, world["a"]["org"].id)

    assert await repository.get(world["b"]["submission"].id) is None


async def test_the_same_retrieval_raises_an_audit_event(two_orgs):
    """The §S20 exit proof, second half — and the only record there is."""
    session, world, sessionmaker = two_orgs
    actor = uuid.uuid4()
    repository = SubmissionRepository(session, world["a"]["org"].id, actor_id=actor)

    await repository.get(world["b"]["submission"].id)

    rows = await _audit_rows(sessionmaker)
    assert len(rows) == 1
    assert rows[0].org_id == world["a"]["org"].id
    assert rows[0].actor_id == actor
    assert rows[0].resource == "submissions"
    assert rows[0].resource_id == str(world["b"]["submission"].id)


async def test_the_audit_row_does_not_name_the_org_it_belonged_to(two_orgs):
    """Knowing it belonged to *someone else* is what a reviewer needs. Naming the
    owner would put one tenant's identity into another tenant's audit trail —
    readable by that tenant's own partner."""
    session, world, sessionmaker = two_orgs
    await SubmissionRepository(session, world["a"]["org"].id).get(world["b"]["submission"].id)

    row = (await _audit_rows(sessionmaker))[0]
    assert str(world["b"]["org"].id) not in str(row.meta)
    assert str(world["b"]["org"].id) not in str(row.resource)


async def test_the_audit_row_survives_the_rollback_a_denial_causes(two_orgs):
    """The reason `record_out_of_band` exists.

    A denial ends in an HTTPException, and the request session is rolled back
    when it does. An audit row written on that session would be discarded with
    the 404 — the record would vanish at exactly the moment it mattered.
    """
    session, world, sessionmaker = two_orgs
    await SubmissionRepository(session, world["a"]["org"].id).get(world["b"]["submission"].id)

    await session.rollback()

    assert len(await _audit_rows(sessionmaker)) == 1


async def test_an_ordinary_miss_inside_your_own_org_is_not_audited(two_orgs):
    """Otherwise a stale bookmark writes an intrusion record and the real signal
    drowns in noise."""
    session, world, sessionmaker = two_orgs
    await SubmissionRepository(session, world["a"]["org"].id).get(uuid.uuid4())

    assert await _audit_rows(sessionmaker) == []


async def test_a_legitimate_read_is_not_audited(two_orgs):
    session, world, sessionmaker = two_orgs
    repository = SubmissionRepository(session, world["a"]["org"].id)

    assert await repository.get(world["a"]["submission"].id) is not None
    assert await _audit_rows(sessionmaker) == []


async def test_repeated_probing_leaves_one_row_per_attempt(two_orgs):
    """A sweep is what this is for. It has to be countable."""
    session, world, sessionmaker = two_orgs
    repository = SubmissionRepository(session, world["a"]["org"].id)

    for _ in range(5):
        await repository.get(world["b"]["submission"].id)

    assert len(await _audit_rows(sessionmaker)) == 5


async def test_a_failed_audit_write_never_converts_a_404_into_a_500(two_orgs):
    """An attacker who could break the audit write would otherwise gain a louder
    oracle than the 404 they were given."""
    session, world, _ = two_orgs
    import app.configs.dbConfig as db_config

    def _broken():
        raise RuntimeError("audit database unreachable")

    original = db_config.get_sessionmaker
    db_config.get_sessionmaker = _broken  # type: ignore[assignment]
    try:
        assert await SubmissionRepository(session, world["a"]["org"].id).get(
            world["b"]["submission"].id
        ) is None
    finally:
        db_config.get_sessionmaker = original  # type: ignore[assignment]
