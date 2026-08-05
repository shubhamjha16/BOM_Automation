"""Our own AIBOM. **We ship what we ask for** (§11).

A tool that assesses other organisations' conformance while publishing none of
its own is the first thing a reviewer notices, and rightly. So this declares
every model the product uses, in the form s.9.3 requires of anyone else.

**9.3(15) Intended Usage and 9.3(16) Out-of-Scope Usage are authored here by
hand, and that is the point.** They are governance declarations no tool can
infer — the same reason they score `not_determinable` for every supplier we
assess. We can supply ours because we are the deploying organisation; a supplier
cannot supply theirs because they are not.

The out-of-scope statement says plainly that this product does not issue legal or
regulatory opinions. That is the honest limit of a conformance engine, and a
client who reads an assessment as legal advice has been misled by our silence.
"""

from __future__ import annotations

from typing import Any

from app.configs.envConfig import settings

#: Every model this product sends data to. Adding one without adding it here is
#: the failure the self-AIBOM exists to make visible.
MODELS: tuple[dict[str, Any], ...] = (
    {
        "name": settings.ROUTER_MODEL,
        "version": "as-served",
        "type": "large language model",
        "architecture": "transformer",
        "developer": "Meta Platforms, served by Groq",
        "license": "Llama 3.3 Community License",
        "task": "intake classification and cheap structural checks",
        "training_data": "not disclosed by the developer",
        "inputs": "BOM metadata and structural summaries; never full BOM payloads",
        "outputs": "classification labels and routing decisions",
        "limitations": (
            "produces no verdict, figure or clause reference; those come from "
            "services/score and services/catalogue and are enforced in code"
        ),
    },
    {
        "name": settings.DRAFTER_MODEL,
        "version": "as-served",
        "type": "large language model",
        "architecture": "transformer",
        "developer": "Anthropic",
        "license": "Commercial, per Anthropic's terms",
        "task": "assessment narrative, VEX justification drafting, critic loop",
        "training_data": "not disclosed by the developer",
        "inputs": "computed verdicts, scores and clause references as inputs to restate",
        "outputs": "prose only; never a status, verdict, figure or clause",
        "limitations": (
            "drafts VEX justifications but never sets a VEX status — the four "
            "statuses of rec. 7.1.6 are an analyst's determination"
        ),
    },
)

#: 9.3(15). Authored by us, because only the deploying organisation can state it.
INTENDED_USAGE = (
    "BOM Automation assesses Bill of Materials submissions against the CERT-In "
    "Technical Guidelines v2.0 and produces a clause-referenced conformance "
    "assessment. Language models are used for three things only: classifying "
    "intake, drafting narrative prose about verdicts the deterministic engine "
    "already computed, and assembling evidence for a VEX justification that an "
    "analyst then determines. Every verdict, score and clause reference is "
    "produced by deterministic code and is enforced as such by a blocking gate."
)

#: 9.3(16). The uses ruled out, and the control that prevents each.
OUT_OF_SCOPE_USAGE = (
    "This product does not issue legal or regulatory opinions. A conformance "
    "assessment states whether a submission meets the minimum elements of a "
    "published technical guideline; it does not establish legal compliance, "
    "contractual adequacy or regulatory standing, and it must not be relied upon "
    "as advice on any of those. "
    "It does not determine VEX status: the four statuses of recommendation 7.1.6 "
    "are an analyst's professional judgement and the API refuses an agent-set "
    "status. "
    "It does not certify a supplier, and a passing score is not an assurance that "
    "software is secure — it states that the declaration is complete, not that "
    "what was declared is safe. "
    "It is not a vulnerability scanner and does not test running systems."
)


def build() -> dict[str, Any]:
    """A CycloneDX 1.6 AIBOM for this product."""
    from datetime import UTC, datetime

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(),
            "authors": [{"name": "BOM Automation"}],
            "component": {"type": "application", "name": "bom-automation", "version": "0.1.0"},
            "properties": [
                {"name": "certin:9.3(15):intended_usage", "value": INTENDED_USAGE},
                {"name": "certin:9.3(16):out_of_scope_usage", "value": OUT_OF_SCOPE_USAGE},
            ],
        },
        "components": [
            {
                "type": "machine-learning-model",
                "bom-ref": f"{model['name']}@{model['version']}",
                "name": model["name"],
                "version": model["version"],
                "supplier": {"name": model["developer"]},
                "licenses": [{"license": {"name": model["license"]}}],
                "modelCard": {
                    "modelParameters": {
                        "modelArchitecture": model["architecture"],
                        "task": model["task"],
                        "datasets": [{"name": model["training_data"]}],
                        "inputs": [{"format": model["inputs"]}],
                        "outputs": [{"format": model["outputs"]}],
                    },
                    "considerations": {"technicalLimitations": [model["limitations"]]},
                },
            }
            for model in MODELS
        ],
    }

def main() -> int:
    """Write the document to ``dist/``. **This exists because it did not.**

    Both self-BOMs were produced by hand once and committed, so when the product
    was renamed they silently kept the old name while every other published
    artifact moved. An artifact §11 promises to publish per release needs a
    command that regenerates it, or it drifts exactly like this.
    """
    import json
    from pathlib import Path

    document = build()
    destination = Path(__file__).resolve().parents[4] / "dist" / "bom-automation.aibom.cdx.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(document, indent=2) + "\n")
    print(f"  {destination.name}: {len(document.get('components') or [])} components")
    return 0


if __name__ == "__main__":  # pragma: no cover - console entry point
    raise SystemExit(main())
