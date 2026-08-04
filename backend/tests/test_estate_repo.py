"""S16 + S17: HBOM, estate rollup, drift, repo generation and the diff.

**What is not established here.** S17's exit proof includes an attempted network
egress being *blocked* during generation. That requires a container runtime, and
Docker is not installed on this machine — so what is tested is that the sandbox
**refuses** untrusted work when it cannot isolate it, which is the behaviour that
makes the missing proof safe rather than dangerous.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest

from app.services.catalogue.hbom import SOURCE_NOTE
from app.services.catalogue.loader import get_catalogue
from app.services.correlate.engine import correlate
from app.services.estate import release_trend, requires_reassessment, rollup, supplier_row
from app.services.ingest.parsers.assetRegister import (
    UnreadableRegister,
    build_column_map,
    parse,
)
from app.services.repo import manifest
from app.services.repo.classification import (
    Classification,
    ClassificationNotDerivable,
    assert_repo_derivable,
    classify_generation,
)
from app.services.repo.connect import Provider, ScopeTooBroad, assert_scopes_minimal
from app.services.repo.diff import compare, component_key
from app.services.repo.sandbox import (
    Isolation,
    LocalSandbox,
    SandboxLimits,
    SandboxUnavailable,
    get_sandbox,
    isolation_report,
)

REGISTER = """Asset Name,Model No,Serial No,OEM,Country of Origin,Vendor,Firmware,Compliance,Rack
Edge Router,MX204,SN-001,Juniper,Malaysia,Acme Dist,21.4R3,BIS;CE,DC1-R7
Core Switch,QFX5120,SN-002,Juniper,Malaysia,Acme Dist,22.1R1,BIS,DC1-R8
"""


def _field(key, clause, verdict, tier="critical", coverage=1.0):
    return {
        "element_key": key,
        "clause": clause,
        "verdict": verdict,
        "tier": tier,
        "coverage": coverage,
        "label": key,
    }


# --- S16: HBOM is procurement data, and says so -----------------------------


def test_the_hbom_catalogue_encodes_table_11():
    catalogue = get_catalogue("hbom")
    clauses = {element.clause for element in catalogue.elements}

    assert len(catalogue.elements) >= 12
    assert "10.2.4" in clauses, "the firmware clause the S9 pairing rule cites"
    assert all(element.clause.startswith("10.2") for element in catalogue.elements)


def test_the_source_note_distinguishes_a_purchase_order_from_a_scan():
    """§11: a reader must be able to tell which claims rest on which."""
    assert "procurement-sourced" in SOURCE_NOTE
    assert "not from scanning an artifact" in SOURCE_NOTE
    assert "not a tooling gap" in SOURCE_NOTE


def test_subcomponent_recursion_is_modelled():
    """Table 11's final row: a server contains boards contain chips."""
    element = get_catalogue("hbom").by_key("subcomponents")
    assert "parent_item_id" in element.rationale or "recursion" in element.rationale


# --- S16: asset-register ingestion -------------------------------------------


def test_real_world_column_names_are_matched_not_positional():
    """ "Serial No", "serial_number" and "Asset Serial" are the same column; a
    positional parser would map warranty into technology node."""
    mapping = build_column_map(["Asset Name", "Model No", "Serial No", "OEM", "Vendor"])
    assert mapping["Serial No"] == "serial_number"
    assert mapping["OEM"] == "manufacturer"
    assert mapping["Vendor"] == "supplier_name"


def test_unmapped_columns_are_preserved_not_dropped():
    """The register's own columns are evidence too."""
    entity = parse(REGISTER, lane="hbom").entities[0]
    assert entity["fields"] == {"Rack": "DC1-R7"}


def test_entry_conservation_holds_for_a_register():
    """The same rule as CycloneDX: a silent drop inflates every percentage."""
    text = REGISTER + ",,,,,,,,\n"
    result = parse(text, lane="hbom")

    assert result.parsed_count == 2
    assert result.rejected_count == 1
    assert result.parsed_count + result.rejected_count == result.declared_entries
    assert "identifies no asset" in result.rejected[0].reason


def test_a_register_with_no_recognisable_columns_is_refused():
    """An empty hardware list renders as a clean assessment of an unread estate."""
    with pytest.raises(UnreadableRegister, match="Refusing to parse"):
        parse("alpha,beta,gamma\n1,2,3\n", lane="hbom")


def test_a_register_without_headers_is_refused():
    with pytest.raises(UnreadableRegister):
        parse("", lane="hbom")


def test_an_asset_register_is_scored_by_the_hbom_lane_only():
    with pytest.raises(UnreadableRegister, match="HBOM lane only"):
        parse(REGISTER, lane="sbom")


# --- S16: firmwareInHbom activates -------------------------------------------


def test_firmware_with_no_sbom_coverage_raises_the_pairing_finding():
    """The S9 rule, declared-but-pending since then, now firing."""
    report = correlate(
        {
            "sbom": [{"name": "openssl", "purl": "pkg:generic/openssl@3.0"}],
            "hbom": [
                {"product_name": "Edge Router", "firmware_version": "21.4R3"},
                {"product_name": "Core Switch", "firmware_version": "22.1R1"},
            ],
        }
    )
    findings = {item.rule_key: item for item in report.findings}

    assert "firmwareInHbom" in findings
    assert findings["firmwareInHbom"].clause == "10.2.4"
    assert "Edge Router" in findings["firmwareInHbom"].detail


def test_firmware_covered_by_the_sbom_raises_nothing():
    report = correlate(
        {
            "sbom": [{"name": "edge router"}],
            "hbom": [{"product_name": "Edge Router", "firmware_version": "21.4R3"}],
        }
    )
    assert "firmwareInHbom" not in [item.rule_key for item in report.findings]


# --- S16: estate rollup and drift --------------------------------------------


def _releases():
    healthy = [_field("license", "4.2(5)", "present"), _field("version", "4.2(2)", "present")]
    dropped = [
        _field("license", "4.2(5)", "present"),
        _field("version", "4.2(2)", "absent", coverage=0.3),
    ]
    worse = [
        _field("license", "4.2(5)", "absent", coverage=0.1),
        _field("version", "4.2(2)", "absent", coverage=0.3),
    ]
    return [
        {"release": "1.0", "released_on": "2026-01-01", "score": 90.0, "fields": healthy},
        {"release": "1.1", "released_on": "2026-03-01", "score": 70.0, "fields": dropped},
        {"release": "1.2", "released_on": "2026-06-01", "score": 55.0, "fields": worse},
    ]


def test_three_releases_produce_a_trend_where_every_movement_traces_to_a_field():
    """The §S16 exit proof. A client asking "why did this drop?" gets clauses,
    not a slope."""
    report = release_trend("Edge Router", _releases()).as_report()

    assert report["direction"] == "regressing"
    assert len(report["points"]) == 3
    assert len(report["movements"]) == 2
    assert report["movements"][0]["regressed"] == ["4.2(2)"]
    assert report["movements"][1]["regressed"] == ["4.2(5)"]


def test_a_release_dropping_a_previously_present_field_raises_drift():
    """The §S16 exit proof, and what s.2.3 re-assessment exists to surface."""
    drift = release_trend("Edge Router", _releases()).drift

    assert len(drift) == 2
    assert drift[0].clause == "4.2(2)"
    assert drift[0].before == "present"
    assert "regressed on a minimum element it had already met" in drift[0].detail


def test_a_release_that_only_improves_raises_no_drift():
    releases = list(reversed(_releases()))
    for index, release in enumerate(releases):
        release["released_on"] = f"2026-0{index + 1}-01"
    assert release_trend("x", releases).drift == []


def test_the_estate_is_sorted_so_the_first_screen_is_the_work_queue():
    """The §S16 exit proof: every supplier's score and worst gap on one screen."""
    rows = rollup(
        {
            "Globex": [
                {"score": 82.0, "assessed_at": "2026-05", "fields": _releases()[0]["fields"]}
            ],
            "Acme": [
                {"score": 90.0, "assessed_at": "2026-01", "fields": _releases()[0]["fields"]},
                {"score": 55.0, "assessed_at": "2026-06", "fields": _releases()[2]["fields"]},
            ],
        }
    )
    # Acme regressed, so it sorts above the higher-scoring Globex.
    assert rows[0].supplier == "Acme"
    assert rows[0].open_regressions == 2
    assert rows[0].worst_gap["clause"] == "4.2(5)"


def test_a_single_submission_reports_no_trend_rather_than_inventing_one():
    row = supplier_row("Acme", [{"score": 70.0, "assessed_at": "2026-01", "fields": []}])
    assert row.trend == "insufficient_history"


def test_any_release_change_triggers_reassessment():
    """s.2.3: every release, update and patch — not a semver comparison, because
    a supplier's versioning scheme is not ours to interpret."""
    assert requires_reassessment("1.0.0", "1.0.1")
    assert requires_reassessment("1.0.0", "2.0.0")
    assert not requires_reassessment("1.0.0", "1.0.0")


# --- S17: classification honesty ---------------------------------------------


@pytest.mark.parametrize("classification", [Classification.DESIGN, Classification.RUNTIME])
def test_design_and_runtime_cannot_come_from_a_repository(classification):
    """The §S17 exit proof. Neither is derivable from static source."""
    with pytest.raises(ClassificationNotDerivable, match="cannot be derived"):
        assert_repo_derivable(classification)


@pytest.mark.parametrize(
    "classification",
    [Classification.SOURCE, Classification.BUILD, Classification.ANALYZED],
)
def test_the_three_repo_derivable_classifications_are_permitted(classification):
    assert_repo_derivable(classification)


def test_a_generation_reports_its_classification_with_the_reason():
    built, reason = classify_generation(built=True, fully_locked=True)
    assert built is Classification.BUILD
    assert "actually resolved and linked" in reason

    source, reason = classify_generation(built=False, fully_locked=False)
    assert source is Classification.SOURCE
    assert "may differ from what a build would resolve" in reason


# --- S17: manifest detection --------------------------------------------------


def test_this_repository_is_detected_as_polyglot():
    ecosystems = manifest.detect(Path(__file__).resolve().parent.parent.parent)
    names = {item.name for item in ecosystems}

    assert {"python", "npm"} <= names
    assert manifest.summarise(ecosystems)["polyglot"] is True


def test_a_lockfile_supersedes_a_bare_manifest():
    with tempfile.TemporaryDirectory() as workspace:
        root = Path(workspace)
        (root / "package.json").write_text("{}")
        (root / "yarn.lock").write_text("")
        detected = manifest.detect(root)

    assert detected[0].manifest == "yarn.lock"
    assert detected[0].locked is True


def test_vendored_directories_are_not_reported_as_the_repositorys_own():
    with tempfile.TemporaryDirectory() as workspace:
        root = Path(workspace)
        (root / "node_modules" / "dep").mkdir(parents=True)
        (root / "node_modules" / "dep" / "Cargo.toml").write_text("")
        (root / "package.json").write_text("{}")
        assert {item.name for item in manifest.detect(root)} == {"npm"}


def test_a_repository_with_no_manifest_reports_it_rather_than_generating_nothing():
    """The §S17 exit proof. An empty SBOM renders as a clean assessment."""
    with tempfile.TemporaryDirectory() as workspace:
        (Path(workspace) / "README.md").write_text("nothing here")
        with pytest.raises(manifest.NoEcosystemDetected, match="no ecosystem|no recognisable"):
            manifest.require(Path(workspace))


# --- S17: the sandbox ---------------------------------------------------------


def test_the_sandbox_refuses_untrusted_work_it_cannot_isolate():
    """The behaviour that makes the missing egress proof safe rather than
    dangerous: dependency resolution executes code from the repository under
    assessment, so unprotected execution is refused outright."""
    sandbox = get_sandbox()
    if not isinstance(sandbox, LocalSandbox):  # pragma: no cover - has a runtime
        pytest.skip("a container runtime is available; isolation is enforced")

    with tempfile.TemporaryDirectory() as workspace:
        with pytest.raises(SandboxUnavailable, match="refusing to run untrusted code"):
            sandbox.run(["echo", "x"], workspace=Path(workspace), limits=SandboxLimits())


def test_the_isolation_report_states_what_is_actually_enforced():
    """ "Generated in a sandbox" means different things on different machines,
    and a reader is entitled to know which one produced their SBOM."""
    report = isolation_report()

    assert report["isolation"] in {str(Isolation.CONTAINER), str(Isolation.LOCAL)}
    assert isinstance(report["network_isolated"], bool)
    # The degraded backend must never claim to permit untrusted sources.
    if report["isolation"] == str(Isolation.LOCAL):
        assert report["network_isolated"] is False
        assert report["untrusted_sources_permitted"] is False
        assert any("NO network isolation" in item for item in report["guarantees"])


def test_a_trusted_local_run_is_permitted_and_reports_its_limits():
    sandbox = get_sandbox()
    if not isinstance(sandbox, LocalSandbox):  # pragma: no cover
        pytest.skip("a container runtime is available")

    with tempfile.TemporaryDirectory() as workspace:
        result = sandbox.run(
            ["echo", "generated"], workspace=Path(workspace), limits=SandboxLimits(), trusted=True
        )
    assert result.exit_code == 0
    assert result.isolation is Isolation.LOCAL
    assert "NO network isolation" in " ".join(result.guarantees)


# --- S17: connection scope ----------------------------------------------------


def test_an_over_scoped_installation_is_refused():
    """Holding write access to a client's source is a liability whether or not
    it is used."""
    with pytest.raises(ScopeTooBroad, match="must never hold"):
        assert_scopes_minimal(Provider.GITHUB, ("contents:read", "contents:write"))


def test_a_read_only_installation_is_accepted():
    assert_scopes_minimal(Provider.GITHUB, ("contents:read", "metadata:read"))


# --- S17: the diff ------------------------------------------------------------


def test_undeclared_components_are_listed_component_by_component():
    """The §S17 exit proof, and the sprint's real output."""
    repo = [
        {"name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"},
        {"name": "left-pad", "version": "1.3.0", "purl": "pkg:npm/left-pad@1.3.0"},
        {"name": "minimist", "version": "1.2.5", "purl": "pkg:npm/minimist@1.2.5"},
    ]
    supplier = [{"name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"}]

    report = compare(repo, supplier).as_report()
    assert [item["name"] for item in report["only_in_repo"]] == ["left-pad", "minimist"]
    assert report["matched"] == 1


def test_a_version_mismatch_is_reported_separately_from_an_absence():
    """Vulnerability matching is version-exact: a supplier declaring a patched
    version they do not ship is worse than declaring nothing."""
    repo = [{"name": "express", "version": "4.18.0", "purl": "pkg:npm/express@4.18.0"}]
    supplier = [{"name": "express", "version": "4.18.2", "purl": "pkg:npm/express@4.18.2"}]

    report = compare(repo, supplier).as_report()
    assert report["only_in_repo"] == []
    assert report["version_mismatch"][0]["repo_version"] == "4.18.0"
    assert report["version_mismatch"][0]["supplier_version"] == "4.18.2"


def test_naming_variants_do_not_manufacture_differences():
    """The same component appears as `lodash`, `Lodash` and `pkg:npm/lodash`
    across tools; a naive comparison would report the whole SBOM as mismatched."""
    repo = [{"name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"}]
    supplier = [{"name": "Lodash", "version": "v4.17.21", "purl": "pkg:npm/lodash@4.17.21"}]

    assert compare(repo, supplier).is_clean


def test_the_key_excludes_the_version_it_is_comparing():
    assert component_key({"purl": "pkg:npm/lodash@4.17.21"}) == component_key(
        {"purl": "pkg:npm/lodash@5.0.0"}
    )


def test_a_declared_component_absent_from_the_repo_is_a_discrepancy_not_a_defect():
    repo: list[dict] = []
    supplier = [{"name": "platform-shim", "version": "1.0.0"}]
    report = compare(repo, supplier).as_report()

    assert [item["name"] for item in report["only_in_supplier"]] == ["platform-shim"]
    assert report["only_in_repo"] == []


# --- S17: real generation, where cdxgen is available -------------------------


def test_generation_produces_a_scoreable_sbom():
    """cdxgen is available here, so this runs for real rather than being mocked."""
    cdxgen = Path(__file__).resolve().parent.parent.parent / "node_modules" / ".bin" / "cdxgen"
    if not cdxgen.exists():  # pragma: no cover - depends on the machine
        pytest.skip("cdxgen is not installed")

    from app.services.repo.generate import generate

    backend = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory() as workspace:
        repository = Path(workspace) / "repo"
        repository.mkdir()
        for name in ("pyproject.toml", "uv.lock"):
            shutil.copy(backend / name, repository / name)

        generation = generate(repository, trusted=True, cdxgen_path=str(cdxgen))

    assert generation.component_count > 20
    assert generation.classification is Classification.SOURCE
    assert generation.document["bomFormat"] == "CycloneDX"
    # The isolation actually used is reported, never assumed.
    assert generation.isolation["isolation"] in {"container", "local"}
