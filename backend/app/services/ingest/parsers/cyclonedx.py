"""CycloneDX 1.4–1.6 → normalised entities.

Two rules this parser exists to enforce, both from §11:

* **Nothing is dropped silently.** Every entry in the source document becomes
  either a parsed entity or a rejection carrying a reason, and the two counts sum
  to the input count. S6 asserts that across every fixture.
* **An unrecognised document raises.** It never returns an empty component list,
  because an empty list scores as a green assessment of nothing.
"""

from __future__ import annotations

from typing import Any

from app.services.ingest.result import ParseResult

SUPPORTED_SPEC_VERSIONS: frozenset[str] = frozenset({"1.4", "1.5", "1.6"})

#: CycloneDX component types that are AI models rather than software components.
MODEL_TYPES: frozenset[str] = frozenset({"machine-learning-model"})

#: CycloneDX 1.6 cryptographic assets — the CBOM and QBOM lanes' entities.
CRYPTO_TYPES: frozenset[str] = frozenset({"cryptographic-asset"})

#: Which component types each lane scores. A lane never guesses.
LANE_TYPES: dict[str, frozenset[str]] = {
    "aibom": MODEL_TYPES,
    "cbom": CRYPTO_TYPES,
    "qbom": CRYPTO_TYPES,
}


class UnrecognisedDocument(ValueError):
    """The payload is not a CycloneDX document, or not a supported version."""




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


def _annotation_index(document: dict[str, Any]) -> dict[str, list[str]]:
    """Annotation text by the ``bom-ref`` it is about (CycloneDX 1.4+ ``annotations``).

    Feeds the Comments or Notes field (s.4.2(15)): notes "relevant to the software
    component or its inclusion in the SBOM".
    """
    index: dict[str, list[str]] = {}
    for entry in document.get("annotations", []) or []:
        if not isinstance(entry, dict):
            continue
        text = str(entry.get("text") or "").strip()
        if not text:
            continue
        for subject in entry.get("subjects", []) or []:
            index.setdefault(str(subject), []).append(text)
    return index


def _normalise_component(
    component: dict[str, Any],
    dependencies: dict[str, list[str]],
    annotations: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    bom_ref = component.get("bom-ref") or component.get("purl")
    supplier = component.get("supplier")
    return {
        "name": component.get("name"),
        "version": component.get("version"),
        "description": component.get("description"),
        "comment": " ".join((annotations or {}).get(str(bom_ref), [])) or None,
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


def _normalise_crypto(
    component: dict[str, Any],
    vulnerabilities: dict[str, list[str]] | None = None,
    document_signature: Any = None,
) -> dict[str, Any]:
    """A CycloneDX 1.6 ``cryptographic-asset`` flattened to Table 9's shape.

    CycloneDX nests the interesting fields three deep and differently per asset
    type; Table 9 is flat. Flattening here keeps the catalogue probes readable
    and means a future CycloneDX layout change touches one function.

    The same flattening feeds the QBOM lane, whose Table 8 rows are properties of the
    quantum system as a whole: its version, vendor, licence, vulnerabilities and signature
    come from the component's standard fields, and the rows CycloneDX has no field for
    (origin, hardware, communication protocol, software dependencies, environmental impact,
    attestations) are read from ``certin:<field>`` properties, the repo's convention for
    fields the format lacks.
    """
    crypto = component.get("cryptoProperties") or {}
    algorithm = crypto.get("algorithmProperties") or {}
    certificate = crypto.get("certificateProperties") or {}
    protocol = crypto.get("protocolProperties") or {}
    material = crypto.get("relatedCryptoMaterialProperties") or {}

    cipher_suites = protocol.get("cipherSuites") or []
    supplier = component.get("supplier")
    bom_ref = component.get("bom-ref") or component.get("purl")
    entity = {
        "name": component.get("name"),
        "bom_ref": component.get("bom-ref"),
        "asset_type": crypto.get("assetType"),
        "oid": crypto.get("oid"),
        # algorithm
        "primitive": algorithm.get("primitive"),
        "mode": algorithm.get("mode"),
        "crypto_functions": algorithm.get("cryptoFunctions"),
        "classical_security_level": algorithm.get("classicalSecurityLevel"),
        "nist_quantum_security_level": algorithm.get("nistQuantumSecurityLevel"),
        # key / related crypto material
        "key_id": material.get("id") or component.get("bom-ref"),
        "state": material.get("state"),
        "size": material.get("size"),
        "creation_date": material.get("creationDate"),
        "activation_date": material.get("activationDate"),
        # protocol
        "version": protocol.get("version"),
        "cipher_suites": [
            suite.get("name") if isinstance(suite, dict) else suite for suite in cipher_suites
        ]
        or None,
        # certificate
        "subject": certificate.get("subjectName"),
        "issuer": certificate.get("issuerName"),
        "not_valid_before": certificate.get("notValidBefore"),
        "not_valid_after": certificate.get("notValidAfter"),
        "signature_algorithm": certificate.get("signatureAlgorithmRef"),
        "subject_public_key": certificate.get("subjectPublicKeyRef"),
        "format": certificate.get("certificateFormat"),
        "certificate_extension": certificate.get("certificateFileExtension")
        or certificate.get("certificateExtensions"),
        # QBOM Table 8: properties of the system the asset belongs to.
        "system_version": component.get("version"),
        "vendor": supplier.get("name") if isinstance(supplier, dict) else None,
        "publisher": component.get("publisher"),
        "license_expr": _licence_expression(component),
        "vulnerabilities": (vulnerabilities or {}).get(str(bom_ref)) or None,
        "signature": component.get("signature") or document_signature,
    }
    for prop in component.get("properties", []) or []:
        name = str(prop.get("name") or "") if isinstance(prop, dict) else ""
        if name.startswith("certin:") and (field := name[len("certin:") :]):
            entity.setdefault(field, prop.get("value"))
    return entity


def _vulnerability_index(document: dict[str, Any]) -> dict[str, list[str]]:
    """Vulnerability ids by the ``bom-ref`` they affect (CycloneDX ``vulnerabilities``)."""
    index: dict[str, list[str]] = {}
    for entry in document.get("vulnerabilities", []) or []:
        if not isinstance(entry, dict):
            continue
        for affected in entry.get("affects", []) or []:
            if isinstance(affected, dict) and (ref := affected.get("ref")):
                index.setdefault(str(ref), []).append(str(entry.get("id") or "vulnerability"))
    return index


def _normalise_model(
    component: dict[str, Any],
    vulnerabilities: dict[str, list[str]] | None = None,
    document_signature: Any = None,
) -> dict[str, Any]:
    """A CycloneDX ``machine-learning-model`` component plus its modelCard."""
    card = component.get("modelCard") or {}
    parameters = card.get("modelParameters") or {}
    considerations = card.get("considerations") or {}
    supplier = component.get("supplier")
    datasets = parameters.get("datasets") or []
    approach = parameters.get("approach") or {}
    bom_ref = component.get("bom-ref") or component.get("purl")
    return {
        "model_name": component.get("name"),
        "model_version": component.get("version"),
        "model_type": parameters.get("modelArchitecture") or parameters.get("task"),
        "architecture": parameters.get("modelArchitecture"),
        "developer": (supplier.get("name") if isinstance(supplier, dict) else None)
        or component.get("author"),
        "license_expr": _licence_expression(component),
        "software_dependencies": component.get("dependencies"),
        "ml_algorithm": parameters.get("architectureFamily")
        or parameters.get("modelArchitecture")
        or (approach.get("type") if isinstance(approach, dict) else None),
        "training_data": [
            entry.get("name") if isinstance(entry, dict) else entry for entry in datasets
        ]
        or None,
        "datasets": [entry for entry in datasets if entry] or None,
        "inputs": parameters.get("inputs"),
        "outputs": parameters.get("outputs"),
        "metrics": (card.get("quantitativeAnalysis") or {}).get("performanceMetrics"),
        "hardware": parameters.get("computeRequirements"),
        "environmental": considerations.get("environmentalConsiderations"),
        # CycloneDX has no field for the model's security requirements; the repo's
        # convention for such fields is a `certin:` property.
        "security_requirements": next(
            (
                prop.get("value")
                for prop in component.get("properties", []) or []
                if isinstance(prop, dict) and prop.get("name") == "certin:security_requirements"
            ),
            None,
        ),
        "vulnerabilities": (vulnerabilities or {}).get(str(bom_ref)) or None,
        # A signature on the model itself, else the one on the whole document.
        "signature": component.get("signature") or document_signature,
        # Intended Usage and Out of Scope Usage are governance declarations; no artifact
        # carries them, so they are consumer-determined and never read from the BOM.
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

    components = payload.get("components", []) or []
    result = ParseResult(
        spec_version=spec_version,
        format="CycloneDX",
        doc_author=author,
        doc_timestamp=metadata.get("timestamp"),
        doc_name=(metadata.get("component") or {}).get("name"),
        declared_entries=len(components) if isinstance(components, list) else 0,
    )
    dependencies = _dependency_index(payload)
    annotations = _annotation_index(payload)
    vulnerabilities = _vulnerability_index(payload)
    # A lane scores exactly one component type. `sbom` takes everything else,
    # which is why it is expressed as the complement rather than a set.
    wanted = LANE_TYPES.get(lane)

    for ordinal, component in enumerate(components):
        if not isinstance(component, dict):
            result.reject(ordinal, "entry is not an object", payload=component)
            continue
        component_type = component.get("type")
        in_scope = (
            component_type in wanted
            if wanted is not None
            else component_type not in MODEL_TYPES | CRYPTO_TYPES
        )
        if not in_scope:
            result.reject(
                ordinal,
                f"component type {component.get('type')!r} is not scored by the "
                f"{lane} lane",
                payload={"name": component.get("name"), "type": component.get("type")},
                ref=str(component.get("bom-ref") or component.get("purl") or ""),
            )
            continue
        if not component.get("name"):
            result.reject(
                ordinal,
                "component has no name; CycloneDX requires name on every component",
                payload=component,
                ref=str(component.get("bom-ref") or component.get("purl") or ""),
            )
            continue
        if wanted is CRYPTO_TYPES:
            result.entities.append(
                _normalise_crypto(component, vulnerabilities, payload.get("signature"))
            )
        elif wanted is MODEL_TYPES:
            result.entities.append(
                _normalise_model(component, vulnerabilities, payload.get("signature"))
            )
        else:
            result.entities.append(_normalise_component(component, dependencies, annotations))

    result.assert_conserved()
    return result
