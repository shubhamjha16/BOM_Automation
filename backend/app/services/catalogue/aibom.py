"""AIBOM minimum elements — CERT-In s.9.3, guideline v2.0 (09.07.2025).

Anchored by the specification: 9.3(6) Software Dependencies (the S9
``modelDepsInSbom`` correlation rule cites it), 9.3(15) Intended Usage and
9.3(16) Out-of-Scope Usage. The remaining ordinals are provisional pending the
S20 catalogue audit, as in the SBOM lane.

AIBOM is the lane with essentially no tooling, so almost every field arrives from
a hand-authored document rather than a generator. That does not soften the
scoring — it is why the lane matters.
"""

from __future__ import annotations

from app.configs.envConfig import settings
from app.configs.jobTypes import Determinability, Tier
from app.services.catalogue.probes import never, present
from app.services.catalogue.types import Catalogue, MinimumElement

ANCHORED_CLAUSES: dict[str, str] = {
    "software_dependencies": "9.3(6)",
    "intended_usage": "9.3(15)",
    "out_of_scope_usage": "9.3(16)",
}

ELEMENTS: tuple[MinimumElement, ...] = (
    MinimumElement(
        key="model_name",
        label="Model Name",
        clause="9.3(1)",
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=present("model_name", "name"),
    ),
    MinimumElement(
        key="model_version",
        label="Model Version",
        clause="9.3(2)",
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
        label="Model Type / Architecture",
        clause="9.3(3)",
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("model_type", "architecture"),
    ),
    MinimumElement(
        key="developer",
        label="Model Developer",
        clause="9.3(4)",
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=present("developer", "supplier_raw", "author"),
    ),
    MinimumElement(
        key="license",
        label="Model Licence",
        clause="9.3(5)",
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
        clause="9.3(6)",
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
        key="training_data_source",
        label="Training Data Source",
        clause="9.3(7)",
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=present("training_data", "data_source"),
    ),
    MinimumElement(
        key="data_preprocessing",
        label="Data Pre-processing",
        clause="9.3(8)",
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("preprocessing", "data_preprocessing"),
    ),
    MinimumElement(
        key="model_inputs",
        label="Model Inputs",
        clause="9.3(9)",
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("inputs", "model_inputs"),
    ),
    MinimumElement(
        key="model_outputs",
        label="Model Outputs",
        clause="9.3(10)",
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("outputs", "model_outputs"),
    ),
    MinimumElement(
        key="performance_metrics",
        label="Performance Metrics",
        clause="9.3(11)",
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("metrics", "performance"),
    ),
    MinimumElement(
        key="evaluation_results",
        label="Evaluation Results",
        clause="9.3(12)",
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("evaluation", "evaluation_results"),
    ),
    MinimumElement(
        key="known_limitations",
        label="Known Limitations and Biases",
        clause="9.3(13)",
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("limitations", "biases"),
    ),
    MinimumElement(
        key="hardware_requirements",
        label="Hardware / Compute Requirements",
        clause="9.3(14)",
        tier=Tier.CONTEXTUAL,
        determinability=Determinability.AUTO,
        probe=present("hardware", "compute_requirements"),
    ),
    MinimumElement(
        key="intended_usage",
        label="Intended Usage",
        clause="9.3(15)",
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
        label="Out-of-Scope Usage",
        clause="9.3(16)",
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
)

CATALOGUE = Catalogue(
    lane="aibom",
    clause_root="9.3",
    guideline_version=settings.GUIDELINE_VERSION,
    elements=ELEMENTS,
)
