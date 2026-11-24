"""AIBOM minimum elements: CERT-In s.9.3, Table 10, guideline v2.0 (09.07.2025).

Table 10 lists 19 elements by name and numbers none of them, so each is cited by
section, table and name (``9.3 Table 10: Software Dependencies``) and the elements
are declared in the order the table gives them. ``tests/test_guideline_fidelity.py``
compares this catalogue with the table, read from the PDF and checked against its
page images. All 19 are anchored.

The earlier catalogue had 16 elements: it invented ordinals (``9.3(1)`` to ``9.3(16)``)
that the guideline does not contain, lacked six of the table's rows (ML Models and
Algorithms, Data Sets, Security Requirements, Environmental Impact, Vulnerabilities,
Attestations) and held three checks the table does not list (data pre-processing,
evaluation results, known limitations and biases).

Six elements are judgement calls, because the guideline defines each in a sentence and
gives no tier or determinability. ML Models and Algorithms, Data Sets, Environmental
Impact, Vulnerabilities and Attestations are read from the CycloneDX model card,
`vulnerabilities` and `signature`. Security Requirements has no CycloneDX field, so it is
read from a ``certin:security_requirements`` property, the repo's convention for fields
the format lacks (the HBOM lane does the same).

AIBOM is the lane with essentially no tooling, so almost every field arrives from
a hand-authored document rather than a generator. That does not soften the
scoring; it is why the lane matters.
"""

from __future__ import annotations

from app.configs.envConfig import settings
from app.configs.jobTypes import Determinability, Tier
from app.services.catalogue.probes import never, present
from app.services.catalogue.types import Catalogue, MinimumElement, table_clause


def _clause(name: str) -> str:
    return table_clause("9.3", 10, name)


#: Every element is checked against Table 10. Kept beside the catalogue so the test and
#: the audit read the same list.
ANCHORED_CLAUSES: dict[str, str] = {
    "model_name": _clause("Model Name"),
    "model_version": _clause("Model Version"),
    "model_type": _clause("Model Type"),
    "developer": _clause("Model Developer"),
    "license": _clause("Model Licensing Information"),
    "software_dependencies": _clause("Software Dependencies"),
    "ml_models_algorithms": _clause("ML Models and Algorithms"),
    "performance_metrics": _clause("Model Performance Metrics"),
    "training_data_source": _clause("Data Source"),
    "data_sets": _clause("Data Sets"),
    "hardware_requirements": _clause("Hardware"),
    "security_requirements": _clause("Security Requirements"),
    "model_inputs": _clause("Input"),
    "model_outputs": _clause("Output"),
    "intended_usage": _clause("Intended Usage"),
    "out_of_scope_usage": _clause("Out of Scope Usage"),
    "environmental_impact": _clause("Environmental Impact"),
    "vulnerabilities": _clause("Vulnerabilities"),
    "attestations": _clause("Attestations"),
}

#: The clause a correlation rule cites for the model's declared software dependencies.
SOFTWARE_DEPENDENCIES_CLAUSE = ANCHORED_CLAUSES["software_dependencies"]

ELEMENTS: tuple[MinimumElement, ...] = (
    MinimumElement(
        key="model_name",
        label="Model Name",
        clause=ANCHORED_CLAUSES["model_name"],
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=present("model_name", "name"),
    ),
    MinimumElement(
        key="model_version",
        label="Model Version",
        clause=ANCHORED_CLAUSES["model_version"],
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=present("model_version", "version"),
        rationale=(
            "Model weights change without an interface change; an unversioned model "
            "cannot be tied to the evaluation that cleared it."
        ),
    ),
    MinimumElement(
        key="model_type",
        label="Model Type",
        clause=ANCHORED_CLAUSES["model_type"],
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("model_type", "architecture"),
    ),
    MinimumElement(
        key="developer",
        label="Model Developer",
        clause=ANCHORED_CLAUSES["developer"],
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=present("developer", "supplier_raw", "author"),
    ),
    MinimumElement(
        key="license",
        label="Model Licensing Information",
        clause=ANCHORED_CLAUSES["license"],
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=present("license_expr", "licenses"),
        rationale=(
            "Model licences carry field-of-use restrictions that no OSS licence "
            "scanner recognises; the declaration is the only source."
        ),
    ),
    MinimumElement(
        key="software_dependencies",
        label="Software Dependencies",
        clause=ANCHORED_CLAUSES["software_dependencies"],
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=present("software_dependencies", "dependencies"),
        rationale=(
            "Correlated against the SBOM at S9: a dependency declared here and absent "
            "there means the SBOM is incomplete, which is a finding no single lane "
            "could produce."
        ),
    ),
    MinimumElement(
        key="ml_models_algorithms",
        label="ML Models and Algorithms",
        clause=ANCHORED_CLAUSES["ml_models_algorithms"],
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("ml_algorithm", "algorithms"),
        rationale=(
            "The machine-learning model and algorithm behind the system. Read from the "
            "CycloneDX model card's architecture family, architecture or approach."
        ),
    ),
    MinimumElement(
        key="performance_metrics",
        label="Model Performance Metrics",
        clause=ANCHORED_CLAUSES["performance_metrics"],
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("metrics", "performance"),
    ),
    MinimumElement(
        key="training_data_source",
        label="Data Source",
        clause=ANCHORED_CLAUSES["training_data_source"],
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=present("training_data", "data_source"),
    ),
    MinimumElement(
        key="data_sets",
        label="Data Sets",
        clause=ANCHORED_CLAUSES["data_sets"],
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("datasets"),
        rationale=(
            "The datasets the model was trained on, from the CycloneDX model card's "
            "`modelParameters.datasets`. A BOM that declares datasets satisfies both this "
            "row and Data Source, because both are drawn from the same field."
        ),
    ),
    MinimumElement(
        key="hardware_requirements",
        label="Hardware",
        clause=ANCHORED_CLAUSES["hardware_requirements"],
        tier=Tier.CONTEXTUAL,
        determinability=Determinability.AUTO,
        probe=present("hardware", "compute_requirements"),
    ),
    MinimumElement(
        key="security_requirements",
        label="Security Requirements",
        clause=ANCHORED_CLAUSES["security_requirements"],
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("security_requirements"),
        rationale=(
            "The encryption and access-control mechanisms that protect the model's data and "
            "user information. CycloneDX has no model-card field for this, so it is read from "
            "a `certin:security_requirements` property on the model."
        ),
    ),
    MinimumElement(
        key="model_inputs",
        label="Input",
        clause=ANCHORED_CLAUSES["model_inputs"],
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("inputs", "model_inputs"),
    ),
    MinimumElement(
        key="model_outputs",
        label="Output",
        clause=ANCHORED_CLAUSES["model_outputs"],
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("outputs", "model_outputs"),
    ),
    MinimumElement(
        key="intended_usage",
        label="Intended Usage",
        clause=ANCHORED_CLAUSES["intended_usage"],
        tier=Tier.CONTEXTUAL,
        determinability=Determinability.HUMAN,
        probe=never,
        rationale=(
            "A governance declaration about the deploying organisation's own use. "
            "The model's developer states what it was built for; only the deployer "
            "can state what it is being used for."
        ),
        consumer_action=(
            "Issue a written intended-usage statement for this deployment and have it "
            "signed by the accountable owner."
        ),
    ),
    MinimumElement(
        key="out_of_scope_usage",
        label="Out of Scope Usage",
        clause=ANCHORED_CLAUSES["out_of_scope_usage"],
        tier=Tier.CONTEXTUAL,
        determinability=Determinability.HUMAN,
        probe=never,
        rationale=(
            "The uses the deploying organisation has ruled out. A supplier cannot "
            "enumerate the consumer's prohibited uses."
        ),
        consumer_action=(
            "Record the uses ruled out for this deployment, and the control that "
            "prevents each."
        ),
    ),
    MinimumElement(
        key="environmental_impact",
        label="Environmental Impact",
        clause=ANCHORED_CLAUSES["environmental_impact"],
        tier=Tier.CONTEXTUAL,
        determinability=Determinability.AUTO,
        probe=present("environmental"),
        rationale=(
            "The environmental cost of training and deploying the model, from the CycloneDX "
            "model card's `environmentalConsiderations`."
        ),
    ),
    MinimumElement(
        key="vulnerabilities",
        label="Vulnerabilities",
        clause=ANCHORED_CLAUSES["vulnerabilities"],
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("vulnerabilities"),
        rationale=(
            "Known vulnerabilities in the model's components, from the CycloneDX "
            "`vulnerabilities` entries that affect the model. A supplier with none to declare "
            "has no way to say so in the BOM, which is why this is a judgement call."
        ),
    ),
    MinimumElement(
        key="attestations",
        label="Attestations",
        clause=ANCHORED_CLAUSES["attestations"],
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("signature"),
        rationale=(
            "A digital signature for the model or the AIBOM, from the CycloneDX `signature` "
            "on the model or on the document."
        ),
    ),
)

CATALOGUE = Catalogue(
    lane="aibom",
    clause_root="9.3",
    guideline_version=settings.GUIDELINE_VERSION,
    elements=ELEMENTS,
)
