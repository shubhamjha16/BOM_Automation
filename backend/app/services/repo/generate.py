"""Orchestrate cdxgen. **We do not reimplement it.**

cdxgen and syft are mature, free and better at ecosystem detection than anything
this project would write. The CERT-In-specific work happens on top of their
output: the 21 minimum elements (S7), the `pkg:supplier/` identifier (S11), the
conformance score. Rewriting a generator would be a sixth SBOM generator nobody
asked for.

Everything here runs through `sandbox.py`, which refuses untrusted sources when
it cannot isolate them.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.services.repo import manifest, sandbox
from app.services.repo.classification import Classification, classify_generation
from app.utils.logger import get_logger

logger = get_logger(__name__)


class GenerationFailed(RuntimeError):
    """Generation ran and produced nothing usable."""


@dataclass(slots=True)
class Generation:
    """One SBOM produced from a repository, with how it was obtained."""

    document: dict[str, Any]
    classification: Classification
    classification_reason: str
    ecosystems: list[dict[str, Any]]
    isolation: dict[str, Any]
    tool: str
    component_count: int

    def as_report(self) -> dict[str, Any]:
        return {
            "classification": str(self.classification),
            "classification_reason": self.classification_reason,
            "ecosystems": self.ecosystems,
            # Surfaced, not assumed: "generated in a sandbox" means different
            # things on different machines.
            "isolation": self.isolation,
            "tool": self.tool,
            "component_count": self.component_count,
        }


def _cdxgen_command(output: str, spec_version: str = "1.6") -> list[str]:
    return [
        "cdxgen",
        "--no-install-deps",
        "--spec-version",
        spec_version,
        "-o",
        output,
        ".",
    ]


def generate(
    repository: Path,
    *,
    trusted: bool = False,
    built: bool = False,
    limits: sandbox.SandboxLimits | None = None,
    cdxgen_path: str | None = None,
) -> Generation:
    """Detect, generate and classify.

    `trusted` is the operator asserting they already control this source. It only
    has effect where no container runtime is available, and it never grants
    network access — it permits execution without isolation, which is a decision
    a person makes, not a default.
    """
    repository = Path(repository)
    ecosystems = manifest.require(repository)
    summary = manifest.summarise(ecosystems)

    box = sandbox.get_sandbox()
    caps = limits or sandbox.SandboxLimits()
    output = repository / "generated.cdx.json"

    command = _cdxgen_command(output.name)
    if cdxgen_path:
        command[0] = cdxgen_path

    if isinstance(box, sandbox.LocalSandbox):
        result = box.run(command, workspace=repository, limits=caps, trusted=trusted)
    else:
        result = box.run(command, workspace=repository, limits=caps)

    if not output.exists():
        raise GenerationFailed(
            f"cdxgen exited {result.exit_code} and produced no document. "
            f"stderr: {result.stderr[:400]}"
        )

    document = json.loads(output.read_text())
    components = document.get("components") or []

    if not components:
        # The manifest said there was something to find. An empty result means
        # generation failed quietly, and an empty SBOM renders as a clean
        # assessment.
        raise GenerationFailed(
            f"generation produced an SBOM with no components despite detecting "
            f"{', '.join(item.name for item in ecosystems)}. Refusing to return an "
            "empty document, which would render as a clean assessment."
        )

    classification, reason = classify_generation(
        built=built, fully_locked=bool(summary["fully_locked"])
    )
    logger.info(
        "repo_generated",
        components=len(components),
        classification=str(classification),
        isolation=str(box.isolation),
    )

    return Generation(
        document=document,
        classification=classification,
        classification_reason=reason,
        ecosystems=summary["ecosystems"],  # type: ignore[arg-type]
        isolation=sandbox.isolation_report(),
        tool="cdxgen",
        component_count=len(components),
    )
