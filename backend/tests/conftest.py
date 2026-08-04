"""Test configuration.

Required env vars are set before any app module imports, because `envConfig`
validates at import — that fail-fast behaviour is itself under test in
`test_config.py`, which manipulates the environment in a subprocess rather than
in-process for exactly this reason.
"""

from __future__ import annotations

import os

os.environ.setdefault("GROQ_API_KEY", "test-key")
os.environ.setdefault("ANTHROPIC_API_KEY", "test-key")
os.environ.setdefault("JWT_SECRET", "test-secret")
os.environ.setdefault("ENABLED_LANES", "sbom,aibom,cbom,qbom,hbom")

from pathlib import Path  # noqa: E402
from typing import Any  # noqa: E402

import pytest  # noqa: E402

from app.services.graph.state import SubmissionDocument  # noqa: E402


@pytest.fixture(scope="session")
def backend_dir() -> Path:
    """Repo path for subprocess boot tests, which run from a scrubbed cwd."""
    return Path(__file__).resolve().parent.parent


def cyclonedx_document(components: list[dict[str, Any]], *, spec_version: str = "1.6") -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "version": 1,
        "metadata": {
            "timestamp": "2026-01-15T09:00:00Z",
            "authors": [{"name": "Test Supplier Ltd"}],
        },
        "components": components,
    }


def component(
    name: str,
    version: str = "1.0.0",
    *,
    licence: str | None = "Apache-2.0",
    supplier: str | None = "Apache Software Foundation",
    purl: str | None = None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "type": "library",
        "bom-ref": f"{name}@{version}",
        "name": name,
        "version": version,
        "description": f"{name} library",
        "purl": purl or f"pkg:maven/org.example/{name}@{version}",
        "hashes": [{"alg": "SHA-256", "content": "a" * 64}],
    }
    if licence is not None:
        entry["licenses"] = [{"license": {"id": licence}}]
    if supplier is not None:
        entry["supplier"] = {"name": supplier}
    return entry


def model_component(name: str = "claude-sonnet-4-5", version: str = "20250929") -> dict[str, Any]:
    return {
        "type": "machine-learning-model",
        "bom-ref": f"{name}@{version}",
        "name": name,
        "version": version,
        "supplier": {"name": "Anthropic"},
        "licenses": [{"license": {"name": "Commercial"}}],
        "modelCard": {
            "modelParameters": {
                "modelArchitecture": "transformer",
                "task": "text-generation",
                "datasets": [{"name": "proprietary"}],
                "inputs": [{"format": "text"}],
                "outputs": [{"format": "text"}],
            },
            "quantitativeAnalysis": {"performanceMetrics": [{"type": "accuracy"}]},
            "considerations": {"technicalLimitations": ["may produce inaccurate output"]},
        },
    }


@pytest.fixture
def sbom_document() -> SubmissionDocument:
    return SubmissionDocument(
        lane="sbom",
        format="CycloneDX",
        payload=cyclonedx_document([component("tomcat-catalina", "9.0.71")]),
    )


@pytest.fixture
def aibom_document() -> SubmissionDocument:
    return SubmissionDocument(
        lane="aibom",
        format="CycloneDX",
        payload=cyclonedx_document([model_component()]),
    )
