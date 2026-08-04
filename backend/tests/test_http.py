"""The S3 exit proofs, as HTTP.

Runs the real app against a SQLite-backed session by overriding the session
dependency — so routing, validation, serialisation, the error handler and the
body-limit middleware are all genuinely exercised, not mocked.
"""

from __future__ import annotations

import ast
import uuid
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.configs.dbConfig import get_session
from app.main import app
from app.models import Base, Client, Engagement, Org
from tests.conftest import component, cyclonedx_document, model_component

BACKEND = Path(__file__).resolve().parent.parent


@pytest.fixture
async def wired():
    """The app, a database, and two orgs. Yields a client plus both org ids."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    session = factory()
    org_a, org_b = Org(id=uuid.uuid4(), name="Firm A"), Org(id=uuid.uuid4(), name="Firm B")
    session.add_all([org_a, org_b])
    await session.flush()
    client_row = Client(org_id=org_a.id, name="Ministry of X")
    session.add(client_row)
    await session.flush()
    engagement = Engagement(
        org_id=org_a.id,
        client_id=client_row.id,
        title="FY26 procurement review",
        enabled_lanes=["sbom", "aibom"],
    )
    session.add(engagement)
    await session.flush()

    async def _session_override():
        yield session

    app.dependency_overrides[get_session] = _session_override
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as http:
        yield http, org_a, org_b, engagement
    app.dependency_overrides.clear()
    await session.close()
    await engine.dispose()


def _headers(org):
    """A real access token. The dev header is gone — S5 replaced it with JWT."""
    from app.utils.security import issue_token

    token = issue_token(
        user_id=uuid.uuid4(),
        org_id=org.id,
        role="assessor",
        kind="access",
        mfa_satisfied=True,
    )
    return {"Authorization": f"Bearer {token}"}


def _document(lane="sbom", components=None):
    return {
        "lane": lane,
        "format": "CycloneDX",
        "spec_version": "1.6",
        "filename": f"{lane}.cdx.json",
        "payload": cyclonedx_document(
            components if components is not None else [component("tomcat-catalina", "9.0.71")]
        ),
    }


# --- /docs renders a complete spec ------------------------------------------


async def test_openapi_renders_and_covers_every_route(wired):
    http, org_a, *_ = wired
    response = await http.get("/openapi.json")
    assert response.status_code == 200

    schema = response.json()
    paths = set(schema["paths"])
    assert {
        "/api/v1/health",
        "/api/v1/elements",
        "/api/v1/submissions",
        "/api/v1/submissions/{submission_id}",
        "/api/v1/submissions/{submission_id}/commit",
        "/api/v1/jobs",
        "/api/v1/jobs/{job_id}",
    } <= paths
    assert "SubmissionCreate" in schema["components"]["schemas"]


async def test_docs_page_is_served(wired):
    http, *_ = wired
    assert (await http.get("/docs")).status_code == 200


# --- a submission with zero documents is refused, not assessed --------------


async def test_zero_documents_returns_422_naming_the_rule(wired):
    """The §S3 exit proof. An empty submission must never produce an assessment."""
    http, org_a, _, engagement = wired
    response = await http.post(
        "/api/v1/submissions",
        json={"engagement_id": str(engagement.id), "documents": []},
        headers=_headers(org_a),
    )

    assert response.status_code == 422
    body = response.json()
    assert body["detail"] == "submission rejected"
    messages = " ".join(violation["message"] for violation in body["violations"])
    assert "at least one BOM document" in messages
    assert "7.1.2" in messages


async def test_every_violation_is_reported_at_once(wired):
    """A supplier fixing a 100 MB upload one error at a time is a bad afternoon."""
    http, org_a, _, engagement = wired
    payload = cyclonedx_document([component("a")])
    response = await http.post(
        "/api/v1/submissions",
        json={
            "engagement_id": str(engagement.id),
            "documents": [
                {"lane": "sbom", "format": "CycloneDX", "spec_version": "1.2", "payload": payload},
                {"lane": "sbom", "format": "CycloneDX", "spec_version": "1.6", "payload": payload},
            ],
        },
        headers=_headers(org_a),
    )

    assert response.status_code == 422
    fields = {violation["field"] for violation in response.json()["violations"]}
    # Both the unsupported spec version and the duplicated document, together.
    assert "documents[0].spec_version" in fields
    assert "documents[1].checksum" in fields


async def test_a_missing_engagement_id_is_a_422_not_a_500(wired):
    http, org_a, *_ = wired
    response = await http.post(
        "/api/v1/submissions", json={"documents": []}, headers=_headers(org_a)
    )
    assert response.status_code == 422


# --- the happy path ---------------------------------------------------------


async def test_a_valid_submission_is_created_and_then_assessed(wired):
    http, org_a, _, engagement = wired

    created = await http.post(
        "/api/v1/submissions",
        json={
            "engagement_id": str(engagement.id),
            "documents": [
                _document("sbom"),
                {**_document("aibom"), "payload": cyclonedx_document([model_component()])},
            ],
        },
        headers=_headers(org_a),
    )
    assert created.status_code == 201, created.text
    submission = created.json()
    assert submission["status"] == "received"
    # Never zero as a placeholder — nothing has been scored yet.
    assert submission["overall_score"] is None

    detail = await http.get(f"/api/v1/submissions/{submission['id']}", headers=_headers(org_a))
    assert detail.status_code == 200
    assert len(detail.json()["documents"]) == 2

    committed = await http.post(
        f"/api/v1/submissions/{submission['id']}/commit", headers=_headers(org_a)
    )
    assert committed.status_code == 200, committed.text
    body = committed.json()
    # Commit returns the job, not the assessment: the work is asynchronous and a
    # handler that waited would tie scoring to an HTTP timeout.
    assert body["created"] is True
    job_id = body["job_id"]

    job = await http.get(f"/api/v1/jobs/{job_id}", headers=_headers(org_a))
    assert job.json()["status"] == "succeeded"

    lanes = {run["lane"] for run in job.json()["node_runs"] if run["lane"]}
    assert lanes == {"sbom", "cbom", "qbom", "aibom", "hbom"}


async def test_committing_the_same_submission_twice_returns_one_job(wired):
    """One job_id, one execution — the S4 idempotency contract, over HTTP."""
    http, org_a, _, engagement = wired
    created = await http.post(
        "/api/v1/submissions",
        json={"engagement_id": str(engagement.id), "documents": [_document("sbom")]},
        headers=_headers(org_a),
    )
    submission_id = created.json()["id"]

    first = await http.post(
        f"/api/v1/submissions/{submission_id}/commit", headers=_headers(org_a)
    )
    second = await http.post(
        f"/api/v1/submissions/{submission_id}/commit", headers=_headers(org_a)
    )

    assert first.json()["created"] is True
    assert second.json()["created"] is False
    assert first.json()["job_id"] == second.json()["job_id"]


async def test_the_job_and_its_node_runs_are_readable_after_the_assessment(wired):
    http, org_a, _, engagement = wired
    created = await http.post(
        "/api/v1/submissions",
        json={"engagement_id": str(engagement.id), "documents": [_document("sbom")]},
        headers=_headers(org_a),
    )
    committed = await http.post(
        f"/api/v1/submissions/{created.json()['id']}/commit", headers=_headers(org_a)
    )
    job_id = committed.json()["job_id"]

    job = await http.get(f"/api/v1/jobs/{job_id}", headers=_headers(org_a))
    assert job.status_code == 200
    body = job.json()
    assert body["status"] == "succeeded"
    assert body["terminal_at"] is not None

    lanes = {run["lane"] for run in body["node_runs"] if run["lane"]}
    assert lanes == {"sbom", "cbom", "qbom", "aibom", "hbom"}


# --- tenancy over HTTP ------------------------------------------------------


async def test_another_org_cannot_read_the_submission_and_gets_404_not_403(wired):
    """404 rather than 403, so existence does not leak."""
    http, org_a, org_b, engagement = wired
    created = await http.post(
        "/api/v1/submissions",
        json={"engagement_id": str(engagement.id), "documents": [_document("sbom")]},
        headers=_headers(org_a),
    )
    submission_id = created.json()["id"]

    response = await http.get(f"/api/v1/submissions/{submission_id}", headers=_headers(org_b))
    assert response.status_code == 404
    assert "permission" not in response.text.lower()


async def test_a_request_without_an_org_scope_is_refused(wired):
    http, _, _, engagement = wired
    response = await http.post(
        "/api/v1/submissions",
        json={"engagement_id": str(engagement.id), "documents": [_document("sbom")]},
    )
    assert response.status_code == 401


# --- oversized bodies are refused at the edge -------------------------------


async def test_an_oversized_declared_body_is_rejected_before_being_read(wired, monkeypatch):
    """A 300 MB document must not be read into memory and then refused."""
    http, org_a, _, engagement = wired
    response = await http.post(
        "/api/v1/submissions",
        json={"engagement_id": str(engagement.id), "documents": [_document("sbom")]},
        headers={**_headers(org_a), "Content-Length": str(300 * 1024 * 1024)},
    )
    assert response.status_code == 413
    assert "exceeds" in response.json()["detail"]


async def test_the_limit_is_derived_from_max_bom_mb():
    from app.configs.envConfig import settings
    from app.validators.submissionValidator import max_document_bytes

    assert max_document_bytes() == settings.MAX_BOM_MB * 1024 * 1024


# --- layering rules ---------------------------------------------------------


def _route_handlers(path: Path):
    """Functions decorated with @router.<verb>.

    Precise rather than "every function in routers/": `deps.py` holds
    dependencies, not handlers, and the under-15-lines rule is about keeping HTTP
    plumbing thin, not about capping every helper in the package.
    """
    for node in ast.walk(ast.parse(path.read_text())):
        if not isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
                if target.value.id == "router":
                    yield node
                    break


def test_every_route_handler_is_under_fifteen_lines():
    checked = 0
    for path in (BACKEND / "app" / "routers").glob("*.py"):
        for node in _route_handlers(path):
            checked += 1
            length = node.end_lineno - node.lineno + 1
            assert length <= 15, f"{path.name}:{node.name} is {length} lines"
    assert checked >= 10, "the handler scan found suspiciously few routes"


def _called_names(path: Path) -> set[str]:
    """Function names actually *called* in a module.

    Parsed rather than grepped: a substring search matches prose, and the first
    version of this test failed on the word `select()` inside a docstring
    explaining that controllers must not call it.
    """
    called: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Call):
            function = node.func
            if isinstance(function, ast.Name):
                called.add(function.id)
            elif isinstance(function, ast.Attribute):
                called.add(function.attr)
    return called


SQL_CALLS = {"select", "insert", "update", "delete", "execute", "text"}


def test_no_router_builds_a_query():
    """Routers do HTTP. A query in a handler is a query that can forget its scope."""
    for path in (BACKEND / "app" / "routers").glob("*.py"):
        offending = _called_names(path) & SQL_CALLS
        assert not offending, f"{path.name} calls {sorted(offending)}"


def test_controllers_do_not_build_queries():
    """Controllers orchestrate; repositories own SQL.

    `jobController` is the one deliberate exception, exempted by name: it reads
    node_runs through the already-scoped parent job, and giving node_runs its own
    repository for a single query would be ceremony.
    """
    for path in (BACKEND / "app" / "controllers").glob("*.py"):
        if path.name == "jobController.py":
            continue
        offending = _called_names(path) & SQL_CALLS
        assert not offending, f"{path.name} calls {sorted(offending)}"
