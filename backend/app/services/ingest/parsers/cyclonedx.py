"""CycloneDX 1.4–1.6 → normalised entities.

Two rules this parser exists to enforce, both from §11:

* **Nothing is dropped silently.** Every entry in the source document becomes
  either a parsed entity or a rejection carrying a reason, and the two counts sum
  to the input count. S6 asserts that across every fixture.
* **An unrecognised document raises.** It never returns an empty component list,
  because an empty list scores as a green assessment of nothing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SUPPORTED_SPEC_VERSIONS: frozenset[str] = frozenset({"1.4", "1.5", "1.6"})

#: CycloneDX component types that are AI models rather than software components.
MODEL_TYPES: frozenset[str] = frozenset({"machine-learning-model"})


class UnrecognisedDocument(ValueError):
    """The payload is not a CycloneDX document, or not a supported version."""


@dataclass(slots=True)
class ParseResult:
    """Parsed entities plus every entry that did not become one."""

    entities: list[dict[str, Any]] = field(default_factory=list)
    rejected: list[dict[str, Any]] = field(default_factory=list)
    spec_version: str = ""
    doc_author: str | None = None
    doc_timestamp: str | None = None

    @property
    def entry_count(self) -> int:
        return len(self.entities) + len(self.rejected)

    def assert_conserved(self, input_count: int) -> None:
        """parsed + rejected must equal the input entry count. The S6 contract."""
        if self.entry_count != input_count:
            raise AssertionError(
                f"entry conservation violated: {len(self.entities)} parsed + "
                f"{len(self.rejected)} rejected = {self.entry_count}, expected {input_count}"
            )


def _reject(ordinal: int, payload: Any, reason: str) -> dict[str, Any]:
    return {"ord": ordinal, "payload": payload, "parse_status": "rejected", "reason": reason}


def _licence_expression(component: dict[str, Any]) -> str | None:
    """Flatten CycloneDX's licence shapes into one expression string."""
    licences = component.get("licenses")
    if not isinstance(licences, list):
        return None
    parts: list[str] = []
    for entry in licences:
        if not isinstance(entry, dict):
            continue
        if expression := entry.get("expression"):
            parts.append(str(expression))
        elif isinstance(licence := entry.get("license"), dict):
            if value := licence.get("id") or licence.get("name"):
                parts.append(str(value))
    return " AND ".join(parts) if parts else None


def _dependency_index(document: dict[str, Any]) -> dict[str, list[str]]:
    index: dict[str, list[str]] = {}
    for entry in document.get("dependencies", []) or []:
        if isinstance(entry, dict) and (ref := entry.get("ref")):
            index[str(ref)] = [str(item) for item in entry.get("dependsOn", []) or []]
    return index


def _normalise_component(
    component: dict[str, Any], dependencies: dict[str, list[str]]
) -> dict[str, Any]:
    bom_ref = component.get("bom-ref") or component.get("purl")
    supplier = component.get("supplier")
    return {
        "name": component.get("name"),
        "version": component.get("version"),
        "description": component.get("description"),
        "supplier_raw": supplier.get("name") if isinstance(supplier, dict) else None,
        "publisher": component.get("publisher"),
        "author": component.get("author"),
        "license_expr": _licence_expression(component),
        "purl": component.get("purl"),
        "cpe": component.get("cpe"),
        "bom_ref": bom_ref,
        "checksums": [
            hash_entry.get("content")
            for hash_entry in component.get("hashes", []) or []
            if isinstance(hash_entry, dict)
        ],
        "externalReferences": component.get("externalReferences"),
        "dependencies": dependencies.get(str(bom_ref), []) if bom_ref else [],
        "properties": {
            str(prop.get("name")): prop.get("value")
            for prop in component.get("properties", []) or []
            if isinstance(prop, dict)
        },
        # Populated by S10 enrichment and S11 identifier mapping, not by the parser.
        "vulnerabilities": None,
        "patch_status": None,
        "release_date": None,
        "eol_date": None,
        "certin_id": None,
        "supplier_org": None,
    }


def _normalise_model(component: dict[str, Any]) -> dict[str, Any]:
    """A CycloneDX ``machine-learning-model`` component plus its modelCard."""
    card = component.get("modelCard") or {}
    parameters = card.get("modelParameters") or {}
    considerations = card.get("considerations") or {}
    supplier = component.get("supplier")
    datasets = parameters.get("datasets") or []
    return {
        "model_name": component.get("name"),
        "model_version": component.get("version"),
        "model_type": parameters.get("modelArchitecture") or parameters.get("task"),
        "architecture": parameters.get("modelArchitecture"),
        "developer": (supplier.get("name") if isinstance(supplier, dict) else None)
        or component.get("author"),
        "license_expr": _licence_expression(component),
        "software_dependencies": component.get("dependencies"),
        "training_data": [
            entry.get("name") if isinstance(entry, dict) else entry for entry in datasets
        ]
        or None,
        "preprocessing": parameters.get("dataPreprocessing"),
        "inputs": parameters.get("inputs"),
        "outputs": parameters.get("outputs"),
        "metrics": (card.get("quantitativeAnalysis") or {}).get("performanceMetrics"),
        "evaluation": card.get("quantitativeAnalysis"),
        "limitations": considerations.get("ethicalConsiderations")
        or considerations.get("technicalLimitations"),
        "hardware": parameters.get("computeRequirements"),
        # 9.3(15)–(16) are governance declarations; no artifact carries them.
        "intended_usage": None,
        "out_of_scope_usage": None,
    }


def parse(payload: dict[str, Any], *, lane: str = "sbom") -> ParseResult:
    """Parse a CycloneDX document into the entities the given lane scores."""
    if not isinstance(payload, dict) or payload.get("bomFormat") != "CycloneDX":
        raise UnrecognisedDocument(
            "payload is not a CycloneDX document (missing bomFormat=CycloneDX); "
            "refusing to parse rather than returning an empty component list (rec. 7.1.5)"
        )

    spec_version = str(payload.get("specVersion", ""))
    if spec_version not in SUPPORTED_SPEC_VERSIONS:
        raise UnrecognisedDocument(
            f"CycloneDX specVersion {spec_version!r} is not supported; "
            f"supported versions are {sorted(SUPPORTED_SPEC_VERSIONS)}"
        )

    metadata = payload.get("metadata") or {}
    authors = metadata.get("authors") or []
    tools = metadata.get("tools") or {}
    author = None
    if authors and isinstance(authors[0], dict):
        author = authors[0].get("name")
    elif isinstance(tools, dict) and (components := tools.get("components")):
        if isinstance(components[0], dict):
            author = components[0].get("name")

    result = ParseResult(
        spec_version=spec_version,
        doc_author=author,
        doc_timestamp=metadata.get("timestamp"),
    )
    dependencies = _dependency_index(payload)
    wants_models = lane == "aibom"

    for ordinal, component in enumerate(payload.get("components", []) or []):
        if not isinstance(component, dict):
            result.rejected.append(_reject(ordinal, component, "entry is not an object"))
            continue
        is_model = component.get("type") in MODEL_TYPES
        if is_model != wants_models:
            result.rejected.append(
                _reject(
                    ordinal,
                    {"name": component.get("name"), "type": component.get("type")},
                    f"component type {component.get('type')!r} is not scored by the "
                    f"{lane} lane",
                )
            )
            continue
        if not component.get("name"):
            result.rejected.append(_reject(ordinal, component, "component has no name"))
            continue
        result.entities.append(
            _normalise_model(component) if is_model else _normalise_component(
                component, dependencies
            )
        )

    return result
