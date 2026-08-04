"""Ecosystem detection: what a repository is written in.

**A repository with no recognisable manifest reports "no ecosystem detected",
never an empty SBOM.** An empty component list renders as a clean assessment —
the same rule as `ingest/detect.py`, applied at the other end of the pipeline.
Detecting nothing and generating nothing must be distinguishable from detecting
nothing and *saying* nothing.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

#: Manifest filenames per ecosystem. Lockfiles are listed first within each
#: ecosystem because a lockfile means resolved, exact versions — a manifest
#: alone means ranges, and an SBOM built from ranges is a guess about what is
#: actually installed.
ECOSYSTEM_MANIFESTS: dict[str, tuple[str, ...]] = {
    "npm": ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "package.json"),
    "python": (
        "uv.lock",
        "poetry.lock",
        "Pipfile.lock",
        "requirements.txt",
        "pyproject.toml",
        "setup.py",
    ),
    "maven": ("pom.xml",),
    "gradle": ("build.gradle", "build.gradle.kts"),
    "go": ("go.sum", "go.mod"),
    "rust": ("Cargo.lock", "Cargo.toml"),
    "ruby": ("Gemfile.lock", "Gemfile"),
    "php": ("composer.lock", "composer.json"),
    "dotnet": ("packages.lock.json", "*.csproj"),
    "docker": ("Dockerfile",),
}

#: Directories never worth walking: vendored dependencies would be reported as
#: the repository's own ecosystems.
SKIP_DIRECTORIES = frozenset(
    {".git", "node_modules", ".venv", "venv", "vendor", "target", "dist", "build", "__pycache__"}
)

MAX_DEPTH = 4


class NoEcosystemDetected(RuntimeError):
    """Nothing recognisable was found. Reported rather than generating nothing."""


@dataclass(frozen=True, slots=True)
class Ecosystem:
    name: str
    manifest: str
    path: str
    #: True when a lockfile was found: resolved versions rather than ranges.
    locked: bool


def _is_lockfile(filename: str) -> bool:
    lowered = filename.lower()
    return "lock" in lowered or lowered == "go.sum"


def detect(root: Path, *, max_depth: int = MAX_DEPTH) -> list[Ecosystem]:
    """Every ecosystem present, with the manifest that proved it."""
    found: dict[str, Ecosystem] = {}
    root = Path(root)

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if any(part in SKIP_DIRECTORIES for part in relative.parts):
            continue
        if len(relative.parts) > max_depth:
            continue

        for ecosystem, manifests in ECOSYSTEM_MANIFESTS.items():
            for manifest in manifests:
                matched = (
                    path.name == manifest
                    if "*" not in manifest
                    else path.match(manifest)
                )
                if not matched:
                    continue
                locked = _is_lockfile(path.name)
                existing = found.get(ecosystem)
                # A lockfile supersedes a bare manifest for the same ecosystem.
                if existing is None or (locked and not existing.locked):
                    found[ecosystem] = Ecosystem(
                        name=ecosystem,
                        manifest=path.name,
                        path=str(relative),
                        locked=locked,
                    )
                break

    return sorted(found.values(), key=lambda item: item.name)


def require(root: Path) -> list[Ecosystem]:
    """Detect, or raise. The caller must not proceed with nothing."""
    ecosystems = detect(root)
    if not ecosystems:
        raise NoEcosystemDetected(
            f"no recognisable dependency manifest found under {root}. Refusing to "
            "generate rather than emitting an empty SBOM, which would render as a "
            "clean assessment of a repository nobody read. Supported ecosystems: "
            f"{', '.join(sorted(ECOSYSTEM_MANIFESTS))}."
        )
    return ecosystems


def summarise(ecosystems: list[Ecosystem]) -> dict[str, object]:
    return {
        "ecosystems": [
            {
                "name": item.name,
                "manifest": item.manifest,
                "path": item.path,
                "locked": item.locked,
            }
            for item in ecosystems
        ],
        "polyglot": len(ecosystems) > 1,
        # Whether every ecosystem resolved to exact versions. A repository with
        # unlocked manifests yields an SBOM of ranges, and the classification
        # below says so.
        "fully_locked": all(item.locked for item in ecosystems),
    }
