"""Derive maturity verdicts from what the platform can observe.

**The rule this module exists to enforce: attested is never evidenced.** It is
the same rule as `not_determinable` never rendering as compliant, applied to a
different question. A scorecard that blends "we saw the workflow file" with "they
told us there is a governance body" is a questionnaire wearing evidence's
clothes, and the whole claim of S19 is that it is not one.

So an `evidenced` verdict **must** carry the artifact that proves it, enforced at
construction. A verdict with no artifact cannot be evidenced — it can only be
attested, or unknown.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from app.services.maturity.roadmap import Activity, by_key


class Verdict(StrEnum):
    MET = "met"
    PARTIAL = "partial"
    NOT_MET = "not_met"
    UNKNOWN = "unknown"


class Basis(StrEnum):
    #: The platform observed it. Carries the artifact that proves it.
    EVIDENCED = "evidenced"
    #: Someone stated it. Carries the question that was asked.
    ATTESTED = "attested"


@dataclass(frozen=True, slots=True)
class ActivityVerdict:
    activity_key: str
    clause: str
    label: str
    verdict: Verdict
    basis: Basis
    #: The file, workflow or record that proves it. Required for EVIDENCED.
    evidence_ref: str | None = None
    detail: str = ""
    #: The question asked. Required for ATTESTED.
    question: str | None = None

    def __post_init__(self) -> None:
        if self.basis is Basis.EVIDENCED and self.verdict in (Verdict.MET, Verdict.PARTIAL):
            if not self.evidence_ref:
                raise ValueError(
                    f"{self.activity_key}: an evidenced verdict must name the artifact "
                    "that proves it. Without one it is an assertion, and asserting is "
                    "what attestation is for."
                )
        if self.basis is Basis.ATTESTED and not self.question:
            raise ValueError(
                f"{self.activity_key}: an attested verdict must carry the question "
                "that was asked, or a reader cannot judge the answer"
            )

    @property
    def is_evidenced(self) -> bool:
        return self.basis is Basis.EVIDENCED

    def as_row(self) -> dict[str, Any]:
        return {
            "activity": self.activity_key,
            "clause": self.clause,
            "label": self.label,
            "verdict": str(self.verdict),
            # Never collapsed into the verdict: the console renders these
            # differently, and so does the report.
            "basis": str(self.basis),
            "evidence_ref": self.evidence_ref,
            "question": self.question,
            "detail": self.detail,
        }


def attested(activity: Activity, verdict: Verdict, *, answer: str = "") -> ActivityVerdict:
    """Record an answer to a question the platform could not observe."""
    if activity.observable:
        raise ValueError(
            f"{activity.key} is observable; recording it as attested would report a "
            "fact we could have checked as something somebody told us"
        )
    return ActivityVerdict(
        activity_key=activity.key,
        clause=activity.clause,
        label=activity.label,
        verdict=verdict,
        basis=Basis.ATTESTED,
        question=activity.question,
        detail=answer or "no answer recorded",
    )


def unknown(activity: Activity) -> ActivityVerdict:
    """Nothing was observed and nothing was asked."""
    return ActivityVerdict(
        activity_key=activity.key,
        clause=activity.clause,
        label=activity.label,
        verdict=Verdict.UNKNOWN,
        basis=Basis.ATTESTED if not activity.observable else Basis.EVIDENCED,
        question=activity.question or None,
        detail="not assessed",
    )


# --- repository observation --------------------------------------------------


@dataclass(frozen=True, slots=True)
class RepositorySignals:
    """What was actually found in a repository. Facts, not judgements."""

    manifests: tuple[str, ...] = ()
    lockfiles: tuple[str, ...] = ()
    workflows: tuple[str, ...] = ()
    sbom_steps: tuple[str, ...] = ()
    audit_steps: tuple[str, ...] = ()
    security_docs: tuple[str, ...] = ()
    install_docs: tuple[str, ...] = ()
    sbom_artifacts: tuple[str, ...] = ()


LOCKFILE_NAMES = (
    "uv.lock",
    "poetry.lock",
    "yarn.lock",
    "package-lock.json",
    "pnpm-lock.yaml",
    "Cargo.lock",
    "go.sum",
    "Gemfile.lock",
    "composer.lock",
)
MANIFEST_NAMES = (
    "pyproject.toml",
    "package.json",
    "requirements.txt",
    "pom.xml",
    "go.mod",
    "Cargo.toml",
)
SECURITY_DOCS = ("SECURITY.md", "security.md", ".github/SECURITY.md")
INSTALL_DOCS = ("README.md", "INSTALL.md", "docs/install.md", "docs/operations.md")
SKIP = frozenset({".git", "node_modules", ".venv", "dist", "build", "__pycache__"})


def observe_repository(root: Path) -> RepositorySignals:
    """Walk a repository and record what is there. No interpretation here."""
    root = Path(root)
    manifests: list[str] = []
    lockfiles: list[str] = []
    workflows: list[str] = []
    sbom_steps: list[str] = []
    audit_steps: list[str] = []
    security_docs: list[str] = []
    install_docs: list[str] = []
    sbom_artifacts: list[str] = []

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if any(part in SKIP for part in relative.parts):
            continue

        name = path.name
        text_path = str(relative)

        if name in LOCKFILE_NAMES:
            lockfiles.append(text_path)
        elif name in MANIFEST_NAMES:
            manifests.append(text_path)
        if text_path in SECURITY_DOCS:
            security_docs.append(text_path)
        if text_path in INSTALL_DOCS:
            install_docs.append(text_path)
        if (
            name.endswith((".cdx.json", ".spdx.json"))
            or "bom" in name.lower()
            and name.endswith(".json")
        ):
            sbom_artifacts.append(text_path)

        if relative.parts[:2] == (".github", "workflows") and name.endswith((".yml", ".yaml")):
            workflows.append(text_path)
            try:
                content = path.read_text(errors="ignore").lower()
            except OSError:  # pragma: no cover
                continue
            if any(token in content for token in ("cdxgen", "syft", "sbom", "cyclonedx")):
                sbom_steps.append(text_path)
            if any(
                token in content
                for token in ("pip-audit", "npm audit", "yarn audit", "trivy", "dependabot", "osv")
            ):
                audit_steps.append(text_path)

    return RepositorySignals(
        manifests=tuple(manifests),
        lockfiles=tuple(lockfiles),
        workflows=tuple(workflows),
        sbom_steps=tuple(sbom_steps),
        audit_steps=tuple(audit_steps),
        security_docs=tuple(security_docs),
        install_docs=tuple(install_docs),
        sbom_artifacts=tuple(sbom_artifacts),
    )


def _evidenced(key: str, verdict: Verdict, ref: str | None, detail: str) -> ActivityVerdict:
    activity = by_key(key)
    return ActivityVerdict(
        activity_key=key,
        clause=activity.clause,
        label=activity.label,
        verdict=verdict,
        basis=Basis.EVIDENCED,
        evidence_ref=ref,
        detail=detail,
    )


@dataclass(frozen=True, slots=True)
class PlatformSignals:
    """What the platform knows about an organisation from its own records."""

    vex_statements: int = 0
    submissions: int = 0
    distinct_periods: int = 0
    releases_assessed: int = 0
    releases_total: int = 0
    boms_access_controlled: bool = True


def derive(
    signals: RepositorySignals, platform: PlatformSignals | None = None
) -> list[ActivityVerdict]:
    """Every observable activity, judged from the signals.

    Each verdict names the artifact it rests on. An activity with no signal is
    `not_met` with the reason — never `unknown`, because we did look.
    """
    platform = platform or PlatformSignals()
    verdicts: list[ActivityVerdict] = []

    verdicts.append(
        _evidenced(
            "inventory_dependencies",
            Verdict.MET if signals.manifests else Verdict.NOT_MET,
            signals.manifests[0] if signals.manifests else None,
            f"{len(signals.manifests)} dependency manifest(s) found"
            if signals.manifests
            else "no dependency manifest found in the repository",
        )
    )
    verdicts.append(
        _evidenced(
            "pin_dependencies",
            Verdict.MET if signals.lockfiles else Verdict.NOT_MET,
            signals.lockfiles[0] if signals.lockfiles else None,
            f"{len(signals.lockfiles)} lockfile(s) found: builds resolve to exact versions"
            if signals.lockfiles
            else "no lockfile: builds resolve version ranges and may differ between runs",
        )
    )
    verdicts.append(
        _evidenced(
            "generate_sbom",
            Verdict.MET if signals.sbom_steps or signals.sbom_artifacts else Verdict.NOT_MET,
            (signals.sbom_steps or signals.sbom_artifacts or (None,))[0],
            "SBOM generation is present in the repository"
            if signals.sbom_steps or signals.sbom_artifacts
            else "no SBOM generation step or artifact found",
        )
    )
    verdicts.append(
        _evidenced(
            "secure_installation",
            Verdict.MET if signals.install_docs else Verdict.NOT_MET,
            signals.install_docs[0] if signals.install_docs else None,
            "installation and operation documentation is published"
            if signals.install_docs
            else "no installation or operation checklist found",
        )
    )
    verdicts.append(
        _evidenced(
            "vulnerability_scanning",
            Verdict.MET if signals.audit_steps else Verdict.NOT_MET,
            signals.audit_steps[0] if signals.audit_steps else None,
            "a dependency audit runs in the pipeline"
            if signals.audit_steps
            else "no dependency-audit step found in any workflow",
        )
    )
    verdicts.append(
        _evidenced(
            "sbom_in_pipeline",
            Verdict.MET if signals.sbom_steps else Verdict.NOT_MET,
            signals.sbom_steps[0] if signals.sbom_steps else None,
            "SBOM generation runs in CI, not only locally"
            if signals.sbom_steps
            else "SBOM generation is not integrated into the pipeline",
        )
    )
    verdicts.append(
        _evidenced(
            "access_controls_on_boms",
            Verdict.MET if platform.boms_access_controlled else Verdict.NOT_MET,
            "repositories/base.py: TenantScopedRepository"
            if platform.boms_access_controlled
            else None,
            "stored BOMs are tenant-scoped at the repository layer"
            if platform.boms_access_controlled
            else "stored BOMs are not access-controlled",
        )
    )
    verdicts.append(
        _evidenced(
            "vex_history",
            Verdict.MET if platform.vex_statements else Verdict.NOT_MET,
            f"{platform.vex_statements} VEX statement(s) in the platform"
            if platform.vex_statements
            else None,
            "a VEX history exists for this organisation"
            if platform.vex_statements
            else "no VEX statements have been authored",
        )
    )
    verdicts.append(
        _evidenced(
            "incident_playbook",
            Verdict.MET if signals.security_docs else Verdict.NOT_MET,
            signals.security_docs[0] if signals.security_docs else None,
            "a disclosure route is published"
            if signals.security_docs
            else "no SECURITY.md or published disclosure route",
        )
    )

    # Cadence: assessed releases against total releases. Partial is the honest
    # middle — some releases assessed is not the same as all of them.
    if platform.releases_total:
        ratio = platform.releases_assessed / platform.releases_total
        cadence = Verdict.MET if ratio >= 0.9 else Verdict.PARTIAL if ratio > 0 else Verdict.NOT_MET
        detail = f"{platform.releases_assessed} of {platform.releases_total} releases assessed"
        ref = "platform submission history"
    else:
        cadence, detail, ref = Verdict.NOT_MET, "no releases recorded", None
    verdicts.append(_evidenced("release_cadence", cadence, ref, detail))

    verdicts.append(
        _evidenced(
            "continuous_monitoring",
            Verdict.MET if platform.distinct_periods >= 2 else Verdict.NOT_MET,
            f"submissions across {platform.distinct_periods} period(s)"
            if platform.distinct_periods >= 2
            else None,
            "conformance is tracked across multiple periods"
            if platform.distinct_periods >= 2
            else "fewer than two assessment periods: no trend can be observed",
        )
    )
    return verdicts


def as_json(verdicts: list[ActivityVerdict]) -> str:
    return json.dumps([verdict.as_row() for verdict in verdicts], indent=2)
