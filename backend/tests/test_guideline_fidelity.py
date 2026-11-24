"""The catalogue must equal the CERT-In guideline, element for element.

``fixtures/certin_v2_elements.json`` lists every minimum element in the order the
published guideline gives them (CERT-In Technical Guidelines on SBOM, QBOM & CBOM,
AIBOM and HBOM, v2.0, 09.07.2025), read from the PDF's tables and checked against
page images. A lane is listed in ``ALIGNED`` once its catalogue matches; the rest
are strict xfails, so the remaining work is visible and fixing a lane forces it to
move here (a strict xfail that starts passing fails the build).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.services.catalogue.loader import get_catalogue

FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "certin_v2_elements.json").read_text())

#: Lanes whose catalogue has been brought into line with the guideline.
ALIGNED = {"sbom"}

#: The guideline's name for each s.4.2 field -> the catalogue key that encodes it.
SBOM_KEY_FOR_NAME = {
    "Component Name": "component_name",
    "Component Version": "version",
    "Component Description": "description",
    "Component Supplier": "supplier_name",
    "Component License": "license",
    "Component Origin": "origin",
    "Component Dependencies": "dependencies",
    "Vulnerabilities": "vulnerabilities",
    "Patch Status": "patch_status",
    "Release Date": "release_date",
    "End-of-Life (EOL) Date": "end_of_life",
    "Criticality": "criticality",
    "Usage Restrictions": "usage_restrictions",
    "Checksums or Hashes": "checksums",
    "Comments or Notes": "comments_notes",
    "Author of SBOM Data": "author_name",
    "Timestamp": "timestamp",
    "Executable Property": "executable_property",
    "Archive Property": "archive_property",
    "Structured Property": "structured_property",
    "Unique Identifier": "certin_identifier",
}


def test_the_fixture_holds_the_guidelines_101_rows():
    counts = {lane: len(data["elements"]) for lane, data in FIXTURE["lanes"].items()}
    assert counts == {"sbom": 21, "qbom": 11, "cbom": 30, "aibom": 19, "hbom": 20}


def test_sbom_matches_the_guideline_in_order_and_numbering():
    expected = [SBOM_KEY_FOR_NAME[row["name"]] for row in FIXTURE["lanes"]["sbom"]["elements"]]
    catalogue = get_catalogue("sbom")
    assert [element.key for element in catalogue.elements] == expected
    # s.4.2 numbers its fields 1-21, and the catalogue cites that number.
    assert [element.clause for element in catalogue.elements] == [
        f"4.2({position})" for position in range(1, len(expected) + 1)
    ]


@pytest.mark.parametrize(
    "lane",
    [
        pytest.param(
            lane,
            marks=pytest.mark.xfail(
                strict=True, reason=f"{lane} catalogue not yet aligned with the guideline"
            ),
        )
        for lane in ("qbom", "cbom", "aibom", "hbom")
    ],
)
def test_other_lanes_have_as_many_elements_as_the_guideline(lane):
    assert len(get_catalogue(lane).elements) == len(FIXTURE["lanes"][lane]["elements"])


def test_every_lane_is_either_aligned_or_tracked():
    assert ALIGNED | {"qbom", "cbom", "aibom", "hbom"} == set(FIXTURE["lanes"])
