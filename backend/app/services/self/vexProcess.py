"""Publish VEX statements for vulnerabilities in our own dependencies.

**We ship what we ask for.** Recommendation 7.1.6 makes VEX the perpetual
obligation for anyone issuing a BOM, and this product issues one for itself. A
tool that demands VEX statements from suppliers while publishing none of its own
has no standing to raise `vexCoverage` against anybody.

Statements here go through exactly the same authoring path a client's would:
`vex/authoring.py` enforces the four statuses, `not_affected` requires a written
justification, and the export is CSAF 2.0.
"""

from __future__ import annotations

import json
from pathlib import Path

from app.services.vex.authoring import VexStatement, author
from app.services.vex.csaf import to_csaf, validate

PUBLISHER = "BOM Automation"
NAMESPACE = "https://github.com/shubhamjha16/BOM_Automation"


def statements() -> list[VexStatement]:
    """Our current determinations.

    Each is an analyst determination — written by a person, not by the evidence
    agent, which drafts justifications and never sets a status.
    """
    return [
        author(
            cve_id="CVE-2024-35195",
            component_ref="requests",
            status="not_affected",
            justification=(
                "The vulnerability requires a Session object to be reused across "
                "requests with verify=False after a prior verified request. Every "
                "outbound call in services/kb uses a fresh httpx.AsyncClient with "
                "verification enabled and never sets verify=False, so the affected "
                "code path is unreachable in this product."
            ),
            authored_by="shubhamjha330@gmail.com",
            evidence_refs=("https://nvd.nist.gov/vuln/detail/CVE-2024-35195",),
        ),
    ]


def build_advisory() -> dict:
    return to_csaf(
        statements(),
        document_title="BOM Automation — VEX statements for declared dependencies",
        publisher_name=PUBLISHER,
        publisher_namespace=NAMESPACE,
        # **Deliberately not renamed with the product.** A CSAF tracking id is the
        # immutable identifier of a published advisory: consumers key off it, and
        # minting a new one for the same CVE produces a second, unrelated-looking
        # advisory with no declared relationship to the first. The publisher *name*
        # above is a display field and does change. This is the discipline we ask
        # of suppliers in `SECURITY.md`, so we keep it ourselves.
        tracking_id="BOMFACTORY-VEX-0001",
    )


def publish(destination: Path | None = None) -> Path:
    """Write the CSAF advisory, refusing to publish one that does not validate."""
    document = build_advisory()
    problems = validate(document)
    if problems:
        raise ValueError(
            "refusing to publish a CSAF document that does not validate: "
            + "; ".join(problems)
        )

    target = destination or Path(__file__).resolve().parents[4] / "dist" / "vex"
    target.mkdir(parents=True, exist_ok=True)
    # Matches the tracking id, and stays put for the same reason: this path is a
    # published URL, and moving it breaks anyone who linked the advisory.
    path = target / "bom-factory-vex-0001.csaf.json"
    path.write_text(json.dumps(document, indent=2) + "\n")
    return path


def main() -> int:
    path = publish()
    document = json.loads(path.read_text())
    print(f"published {len(document['vulnerabilities'])} VEX statement(s) -> {path.name}")
    for entry in document["vulnerabilities"]:
        print(f"  {entry['cve']}  {next(iter(entry['product_status']))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
