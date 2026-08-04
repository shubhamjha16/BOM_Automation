"""SBOM classification, per s.3.2. **Design and Runtime cannot come from a repo.**

The guideline defines six classifications by *what was observed to produce them*:

* **Design (3.2.1)** — from an architecture, before code exists.
* **Source (3.2.2)** — from the manifests in a repository.
* **Build (3.2.3)** — from a build, capturing what was actually linked.
* **Analyzed (3.2.4)** — from inspecting a built artifact.
* **Deployed (3.2.5)** — from an installed system.
* **Runtime (3.2.6)** — from a running process, capturing what is actually loaded.

A repository checkout can support the middle three and cannot support Design or
Runtime: neither is derivable from static source, and claiming otherwise
misrepresents coverage to a reader who is entitled to know how the SBOM was
obtained. That is enforced here rather than trusted, because the difference
between "these are the declared dependencies" and "these are the loaded
libraries" is exactly what a procurement reviewer is trying to establish.
"""

from __future__ import annotations

from enum import StrEnum


class Classification(StrEnum):
    DESIGN = "design"
    SOURCE = "source"
    BUILD = "build"
    ANALYZED = "analyzed"
    DEPLOYED = "deployed"
    RUNTIME = "runtime"


CLAUSES: dict[Classification, str] = {
    Classification.DESIGN: "3.2.1",
    Classification.SOURCE: "3.2.2",
    Classification.BUILD: "3.2.3",
    Classification.ANALYZED: "3.2.4",
    Classification.DEPLOYED: "3.2.5",
    Classification.RUNTIME: "3.2.6",
}

#: The only classifications a repository checkout can honestly support.
REPO_DERIVABLE: frozenset[Classification] = frozenset(
    {Classification.SOURCE, Classification.BUILD, Classification.ANALYZED}
)


class ClassificationNotDerivable(ValueError):
    """A classification was claimed that its evidence cannot support."""


def assert_repo_derivable(classification: Classification) -> None:
    """Raise unless a repository generation could have produced this."""
    if classification not in REPO_DERIVABLE:
        raise ClassificationNotDerivable(
            f"{classification} (clause {CLAUSES[classification]}) cannot be derived "
            f"from a repository. Static source shows declared dependencies, not an "
            f"architecture and not what a process loads at runtime. Repository "
            f"generations may be classified "
            f"{', '.join(sorted(item.value for item in REPO_DERIVABLE))} only — "
            "claiming otherwise misrepresents how the SBOM was obtained."
        )


def classify_generation(*, built: bool, fully_locked: bool) -> tuple[Classification, str]:
    """The honest classification for a repository generation, and why.

    A build was run → Build: what was actually resolved and linked.
    Otherwise → Source: what the manifests declare, which is a weaker claim, and
    weaker still when the manifests are unlocked ranges.
    """
    if built:
        return (
            Classification.BUILD,
            "a build was executed, so the component set reflects what was actually "
            f"resolved and linked (clause {CLAUSES[Classification.BUILD]})",
        )

    if fully_locked:
        return (
            Classification.SOURCE,
            "derived from lockfiles in the repository: exact declared versions, "
            "not observed at build or runtime (clause "
            f"{CLAUSES[Classification.SOURCE]})",
        )

    return (
        Classification.SOURCE,
        "derived from unlocked manifests: the declared version ranges, which may "
        "differ from what a build would resolve (clause "
        f"{CLAUSES[Classification.SOURCE]})",
    )
