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
from typing import Any

from app.configs.dbConfig import get_engine, get_sessionmaker
from app.models import Base, Client, Engagement, Org
from app.models.enums import BomFormat, Role
from app.repositories.corpusRepository import CorpusRepository
from app.repositories.submissionRepository import SubmissionRepository
from app.repositories.userRepository import UserRepository
from app.services.catalogue.seeder import seed as seed_catalogue
from app.services.retrieval.ingest import ingest
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
            {
                "type": "library",
                "bom-ref": "openssl@3.0.0",
                "name": "openssl",
                "version": "3.0.0",
                "supplier": {"name": "OpenSSL Software Foundation"},
            },
        ],
    }


def _sample_aibom() -> dict:
    from app.services.self import aibom

    return aibom.build()


def _sample_cbom() -> dict:
    """A CBOM carrying all four Table 9 asset types, and deliberate defects.

    The defects are the point of a demo: an expired certificate, TLS 1.0 with
    3DES and a SHA-1 signature are each well-declared and each unacceptable, so
    the lane scores highly on completeness and is still capped below `pass`.
    RSA with no PQC migration entry raises the quantum-exposure correlation.
    """

    def asset(name: str, asset_type: str, **properties: Any) -> dict[str, Any]:
        return {
            "type": "cryptographic-asset",
            "bom-ref": name,
            "name": name,
            "cryptoProperties": {"assetType": asset_type, **properties},
        }

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": "2026-01-15T09:00:00Z",
            "authors": [{"name": "Acme Ltd"}],
        },
        "components": [
            asset(
                "RSA-2048",
                "algorithm",
                algorithmProperties={
                    "primitive": "signature",
                    "mode": "pkcs1v15",
                    "classicalSecurityLevel": 112,
                    "cryptoFunctions": ["sign", "verify"],
                },
                oid="1.2.840.113549.1.1.1",
            ),
            asset(
                "AES-256-GCM",
                "algorithm",
                algorithmProperties={
                    "primitive": "ae",
                    "mode": "gcm",
                    "classicalSecurityLevel": 256,
                    "cryptoFunctions": ["encrypt", "decrypt"],
                },
            ),
            asset(
                "api-signing-key",
                "related-crypto-material",
                relatedCryptoMaterialProperties={
                    "id": "key-001",
                    "state": "active",
                    "size": 2048,
                    "creationDate": "2024-01-01",
                    "activationDate": "2024-01-02",
                },
            ),
            asset(
                "tls-edge",
                "protocol",
                protocolProperties={
                    "version": "TLS 1.0",
                    "cipherSuites": [{"name": "TLS_RSA_WITH_3DES_EDE_CBC_SHA"}],
                },
            ),
            asset(
                "tls-internal",
                "protocol",
                protocolProperties={
                    "version": "TLS 1.3",
                    "cipherSuites": [{"name": "TLS_AES_256_GCM_SHA384"}],
                },
            ),
            asset(
                "api-gateway-cert",
                "certificate",
                certificateProperties={
                    "subjectName": "CN=api.acme.example",
                    "issuerName": "CN=Acme Internal CA",
                    "notValidBefore": "2022-01-01",
                    "notValidAfter": "2024-01-15",
                    "signatureAlgorithmRef": "sha1WithRSAEncryption",
                    "certificateFormat": "X.509",
                },
            ),
        ],
    }


#: An asset register as an estate manager would export it — real column names,
#: one row missing its firmware so the HBOM lane has a genuine gap to report.
SAMPLE_ASSET_REGISTER = """Asset Name,Model No,Serial No,OEM,Country of Origin,Vendor,\
Supplier Location,Firmware,Compliance,Warranty,Rack
Edge Router,MX204,SN-84102,Juniper Networks,Malaysia,Acme Distribution,Mumbai,\
21.4R3-S2,BIS;CE,AMC-2027-114,DC1-R07
Core Switch,QFX5120-48Y,SN-84103,Juniper Networks,Malaysia,Acme Distribution,Mumbai,\
22.1R1,BIS,AMC-2027-115,DC1-R08
Firewall,SRX4100,SN-84104,Juniper Networks,China,Acme Distribution,Mumbai,\
,BIS;CE,AMC-2026-902,DC1-R09
"""


# --- the retrieval corpus ----------------------------------------------------
#
# House wording the firm has written before, which the drafter retrieves for its
# *voice* and never for its facts. Seeded with figures and clause references
# still in it, exactly as a real past assessment would arrive — the masker strips
# them on ingest, and the demo shows the stripped result, which is the whole
# argument made visible.

HOUSE_WORDING: list[tuple[str, str, str]] = [
    (
        "past_assessment",
        "Acme Software — FY25 procurement review",
        """Licence coverage

Licences were absent across 388 of 412 components, failing 4.2(5). Partial \
coverage does not satisfy the clause: a declaration covering a quarter of the \
estate has not met it, and we do not report it as met.

We recommend the supplier restate their declaration with SPDX identifiers for \
every component and resubmit. The gap register attached to this assessment lists \
each affected component, and the supplier should work through it in the order \
given rather than by ease of resolution.

Supplier identification

Supplier Name was declared on 41 of 412 components, failing 4.2(4). Because \
4.2(21) is formed from the supplier organisation, the CERT-In identifier could \
not be constructed for the remaining components either — one absence propagates \
into the other, and the consuming organisation should treat the two as a single \
remediation item rather than two.""",
    ),
    (
        "past_assessment",
        "Northwind Systems — FY25 estate assessment",
        """Cryptographic declarations

The submission declared RSA-2048 across 14 assets with no post-quantum \
migration entry, raising quantum exposure under 8.5.1. This is not yet a defect \
in the deployed cryptography; it is an absence of a stated plan, and the \
distinction matters to how the consuming organisation should respond.

Two certificates were past their Not Valid After date as of 2025-07-09, flagged \
under 8.4.3.3. Declaration completeness and configuration acceptability are \
different measurements: the supplier declared these assets correctly and what \
they declared is not acceptable. We report both and cap the lane verdict rather \
than reconciling them into one number.""",
    ),
    (
        "remediation_wording",
        "House remediation language — returning a submission",
        """Returning a submission to the supplier

We are returning this submission with the gap register attached. The register \
lists every unmet minimum element in priority order, with the clause each rests \
on and the count of affected components. The supplier should work through it in \
the order given.

Where a field is marked not determinable, no action is required of the supplier \
— those are determinations the consuming organisation must make, and each row \
states the action required. A resubmission that addresses only the supplier \
rows is complete from the supplier's side.""",
    ),
    (
        "house_style",
        "House style — reporting a consumer determination",
        """Consumer determinations

Criticality and Usage Restrictions cannot be established from a BOM artifact. \
No supplier could have supplied them: criticality is relative to the consuming \
deployment, and usage restrictions are a legal determination about the \
consuming organisation's own obligations.

We therefore exclude both from the supplier's score and report them here \
instead, with the action required of the consuming organisation beside each. A \
reader should not treat an entry in this section as a supplier defect, and a \
supplier should not be asked to remediate one.""",
    ),
]

#: Firm B's corpus. **This exists to be invisible.** It is written to be the best
#: possible match for the demo query — same subject, same vocabulary, more of it —
#: so that if the org scope were ever dropped it would surface as the *first*
#: result rather than somewhere in a tail nobody checks.
COMPETITOR_WORDING = (
    "past_assessment",
    "CONFIDENTIAL — Contoso Ltd, competing firm's assessment",
    """Licence coverage and supplier identification

Licences were absent across 401 of 415 components, failing 4.2(5), and supplier \
names were absent across 372, failing 4.2(4). Licence coverage, licence \
declarations, licensing gaps and supplier identification are the dominant \
findings in this engagement and the client should treat them as one item.

This paragraph belongs to another tenant. If it ever appears in Firm A's \
console, the org scope has been lost and one client's assessment is being read \
while drafting another's.""",
)


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
            # QBOM stays off: this client has no quantum hardware, so the lane
            # reports lane_not_applicable and leaves the overall score alone —
            # which is the distinction the demo should show.
            enabled_lanes=["sbom", "aibom", "cbom", "hbom"],
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
        documents: list[tuple[str, Any]] = [
            ("sbom", _sample_sbom()),
            ("aibom", _sample_aibom()),
            ("cbom", _sample_cbom()),
            # Procurement data, so it arrives as a spreadsheet rather than a BOM.
            ("hbom", {"__text__": SAMPLE_ASSET_REGISTER.replace("\\\n", "")}),
        ]
        for lane, payload in documents:
            await submissions.add_document(
                submission,
                lane=lane,
                format=BomFormat.CYCLONEDX,
                checksum=uuid.uuid4().hex,
                size_bytes=(
                    len(json.dumps(payload)) if isinstance(payload, dict) else len(payload)
                ),
                entry_count=len(payload.get("components") or [])
                if isinstance(payload, dict)
                else 0,
                payload=payload,
            )

        # --- the retrieval corpus -------------------------------------------
        # Ingested through the real path, so the demo shows genuinely masked
        # text rather than fixtures that were written pre-masked.
        corpus = CorpusRepository(session, org.id)
        masked_total = 0
        for kind, title, text in HOUSE_WORDING:
            report = await ingest(corpus, kind=kind, title=title, text=text)
            masked_total += report.masked_facts

        # Firm B exists for one reason: to be invisible. Its document is written
        # to out-match Firm A's on the demo query, so a lost org scope would
        # surface as the first result rather than somewhere nobody looks.
        other_org = Org(id=uuid.uuid4(), name="Firm B (a competing practice)")
        session.add(other_org)
        await session.flush()
        kind, title, text = COMPETITOR_WORDING
        await ingest(
            CorpusRepository(session, other_org.id), kind=kind, title=title, text=text
        )

        await session.commit()

        print("demo data seeded")
        print(f"  catalogue    {version.ref} v{version.version}")
        print(f"  org          Firm A -> {client.name}")
        print(f"  engagement   {engagement.title} (lanes: {', '.join(engagement.enabled_lanes)})")
        print(f"  submission   {submission.id} with {len(documents)} documents, uncommitted")
        print("               sbom + aibom + cbom + hbom (asset register)")
        print(
            f"  corpus       {len(HOUSE_WORDING)} house documents, "
            f"{masked_total} facts masked on ingest"
        )
        print("               + 1 document under Firm B that must never surface")
        print()
        print(f"  sign in as   {DEMO_EMAIL}")
        print(f"  password     {DEMO_PASSWORD}")

    await get_engine().dispose()
    return 0


def main() -> int:
    return asyncio.run(run())


if __name__ == "__main__":
    sys.exit(main())
