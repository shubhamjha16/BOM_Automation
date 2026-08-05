"""S16/S21: the HBOM lane, and how a hardware document is routed.

The routing question is the one that bites. HBOM data is procurement data — a CSV
or XLSX export from an asset register — which is why the lane implies the register
parser. But CycloneDX 1.6 carries hardware as `type: device`, so a CycloneDX HBOM
is a legitimate submission too, and the dispatcher has to tell them apart by shape
rather than by lane.
"""

from __future__ import annotations

# --- S21: routing is by payload shape, not by lane ---------------------------


def test_a_cyclonedx_hbom_is_parsed_rather_than_refused():
    """**Found by the S21 scale measurement**, whose HBOM lane was timing the
    exception path rather than the scoring path.

    The lane implies the asset-register parser because HBOM data is usually
    procurement data. But CycloneDX 1.6 carries hardware as `type: device` and
    s.10.2.4 makes the HBOM-with-SBOM pairing explicit, so a CycloneDX HBOM is a
    legitimate submission. It used to be refused with "an asset register must be
    CSV text or XLSX bytes, got dict" — a message about our own dispatcher, raised
    at a supplier who sent a valid document.
    """
    from app.scripts.scaleProfile import synthetic_hbom
    from app.services.ingest.normalize import ingest_document

    result = ingest_document(synthetic_hbom(4), lane="hbom", declared_format="CycloneDX")

    assert result.parsed_count == 4
    assert result.rejected_count == 0
    assert result.format == "CycloneDX"


def test_a_csv_asset_register_still_routes_to_the_register_parser():
    from app.services.ingest.normalize import is_asset_register

    assert is_asset_register("Asset,Manufacturer\nsw-1,Acme\n", lane="hbom")
    assert is_asset_register(b"\x50\x4b\x03\x04", lane="hbom")


def test_a_self_identifying_bom_is_never_treated_as_a_register():
    from app.services.ingest.normalize import is_asset_register

    assert not is_asset_register({"bomFormat": "CycloneDX"}, lane="hbom")
    assert not is_asset_register({"spdxVersion": "SPDX-2.3"}, lane="hbom")


def test_an_explicit_declaration_still_wins():
    """A caller who says "this is an asset register" is believed, whatever the
    lane — the S16 ingestion path for a spreadsheet attached to a mixed
    submission."""
    from app.services.ingest.normalize import is_asset_register

    assert is_asset_register("a,b\n1,2\n", lane="sbom", declared_format="assetregister-csv")


def test_a_cyclonedx_hbom_scores_against_table_11():
    """Parsing it is not enough — it has to reach the Table 11 catalogue."""
    from app.scripts.scaleProfile import synthetic_hbom
    from app.services.graph.nodes.hbomLane import score_hbom
    from app.services.graph.state import SubmissionDocument

    result = score_hbom(
        [SubmissionDocument(lane="hbom", format="CycloneDX", payload=synthetic_hbom(6))]
    )

    assert result.entity_count == 6
    assert result.score is not None
