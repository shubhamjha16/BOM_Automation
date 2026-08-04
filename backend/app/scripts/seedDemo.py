"""Stand up a clickable demo: SQLite, a seeded catalogue, an account, real BOMs.

**Why SQLite rather than Postgres.** The models were made dialect-portable so the
repository guards could be tested without a live database (S2), and that pays off
here: a demo runs with no Docker, no Postgres and no Redis. Production is
Postgres and the migrations target it; this is a demo path, not a supported
deployment, and it says so.

Run: `make demo` — or `uv run python -m app.scripts.seedDemo` for the data alone.
"""

from __future__ import annotations

import asyncio
import json
import sys
import uuid
from pathlib import Path

from app.configs.dbConfig import get_engine, get_sessionmaker
from app.models import Base, Client, Engagement, Org
from app.models.enums import BomFormat, Role
from app.repositories.submissionRepository import SubmissionRepository
from app.repositories.userRepository import UserRepository
from app.services.catalogue.seeder import seed as seed_catalogue
from app.utils.security import hash_password

DEMO_EMAIL = "assessor@firm-a.example"
DEMO_PASSWORD = "demo-password-1234"
FIXTURES = Path(__file__).resolve().parent.parent.parent / "tests" / "fixtures" / "boms"


def _sample_sbom() -> dict:
    """Real cdxgen output where available, so the demo scores a real BOM."""
    captured = FIXTURES / "cyclonedx" / "cdxgen-backend-1.6.json"
    if captured.exists():
        return json.loads(captured.read_text())
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {"timestamp": "2026-01-15T09:00:00Z", "authors": [{"name": "Acme Ltd"}]},
        "components": [
            {"type": "library", "bom-ref": "openssl@3.0.0", "name": "openssl",
             "version": "3.0.0", "supplier": {"name": "OpenSSL Software Foundation"}},
        ],
    }


def _sample_aibom() -> dict:
    from app.services.self import aibom

    return aibom.build()


async def run() -> int:
    async with get_engine().begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    async with get_sessionmaker()() as session:
        users = UserRepository(session)
        if await users.by_email(DEMO_EMAIL) is not None:
            print(f"demo data already present — sign in as {DEMO_EMAIL}")
            await get_engine().dispose()
            return 0

        version = await seed_catalogue(session, reviewed_by="demo")

        org = Org(id=uuid.uuid4(), name="Firm A")
        session.add(org)
        await session.flush()

        client = Client(org_id=org.id, name="Ministry of Digital Affairs", sector="govt")
        session.add(client)
        await session.flush()

        engagement = Engagement(
            org_id=org.id,
            client_id=client.id,
            title="FY26 procurement review",
            enabled_lanes=["sbom", "aibom"],
        )
        session.add(engagement)
        await session.flush()

        user = await users.create(
            org_id=org.id,
            email=DEMO_EMAIL,
            hashed_password=hash_password(DEMO_PASSWORD),
            role=Role.MANAGER,
        )

        submissions = SubmissionRepository(session, org.id)
        submission = await submissions.create(engagement_id=engagement.id, submitted_by=user.id)
        for lane, payload in (("sbom", _sample_sbom()), ("aibom", _sample_aibom())):
            await submissions.add_document(
                submission,
                lane=lane,
                format=BomFormat.CYCLONEDX,
                checksum=uuid.uuid4().hex,
                size_bytes=len(json.dumps(payload)),
                entry_count=len(payload.get("components") or []),
                payload=payload,
            )

        await session.commit()

        print("demo data seeded")
        print(f"  catalogue    {version.ref} v{version.version}")
        print(f"  org          Firm A -> {client.name}")
        print(f"  engagement   {engagement.title} (lanes: {', '.join(engagement.enabled_lanes)})")
        print(f"  submission   {submission.id} with 2 documents, uncommitted")
        print()
        print(f"  sign in as   {DEMO_EMAIL}")
        print(f"  password     {DEMO_PASSWORD}")

    await get_engine().dispose()
    return 0


def main() -> int:
    return asyncio.run(run())


if __name__ == "__main__":
    sys.exit(main())
