"""Repo-derived SBOM versus supplier-submitted SBOM. **S17's real output.**

A supplier SBOM that omits what the repository contains is the finding a
procurement team cannot obtain any other way. They cannot audit the supplier's
build; they can compare two documents about the same release, and disagreement
is evidence.

**Three findings, and they mean different things:**

* `only_in_repo` — the repository contains a component the supplier did not
  declare. The strongest finding: undeclared components are unassessed for
  licence, vulnerability and lifecycle obligations, and this is what an
  incomplete SBOM looks like from outside.
* `only_in_supplier` — declared but not found in the repository. Usually benign
  (a build-time or platform dependency), occasionally not, and reported as a
  discrepancy to explain rather than a defect.
* `version_mismatch` — both declare it, at different versions. Matters because
  vulnerability matching is version-exact: a supplier declaring a patched version
  they do not ship is worse than declaring nothing.

**Names are compared case-insensitively and PURL-first**, because the same
component appears as `lodash`, `pkg:npm/lodash` and `Lodash` across tools, and a
naive comparison would report the entire SBOM as mismatched.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from app.services.identifiers.purl import try_parse


@dataclass(frozen=True, slots=True)
class ComponentRef:
    key: str
    name: str
    version: str | None

    def as_row(self) -> dict[str, Any]:
        return {"key": self.key, "name": self.name, "version": self.version}


@dataclass(frozen=True, slots=True)
class VersionMismatch:
    key: str
    name: str
    repo_version: str | None
    supplier_version: str | None

    def as_row(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "name": self.name,
            "repo_version": self.repo_version,
            "supplier_version": self.supplier_version,
        }


@dataclass(slots=True)
class GenerationDiff:
    only_in_repo: list[ComponentRef] = field(default_factory=list)
    only_in_supplier: list[ComponentRef] = field(default_factory=list)
    version_mismatch: list[VersionMismatch] = field(default_factory=list)
    matched: int = 0

    @property
    def is_clean(self) -> bool:
        return not (self.only_in_repo or self.only_in_supplier or self.version_mismatch)

    @property
    def undeclared_count(self) -> int:
        """The number that matters most to a procurement reader."""
        return len(self.only_in_repo)

    def as_report(self) -> dict[str, Any]:
        return {
            "matched": self.matched,
            "only_in_repo": [item.as_row() for item in self.only_in_repo],
            "only_in_supplier": [item.as_row() for item in self.only_in_supplier],
            "version_mismatch": [item.as_row() for item in self.version_mismatch],
            "summary": (
                f"{self.matched} component(s) agree; "
                f"{len(self.only_in_repo)} present in the repository and not declared; "
                f"{len(self.only_in_supplier)} declared and not found in the repository; "
                f"{len(self.version_mismatch)} declared at a different version"
            ),
        }


def component_key(entity: dict[str, Any]) -> str:
    """A comparable identity for a component.

    PURL first — it is the one identifier both tools agree on — falling back to a
    lowercased name. Version is deliberately excluded: it is what we are
    comparing, so it cannot be part of the key.
    """
    if purl := try_parse(entity.get("purl")):
        return purl.coordinates.lower()
    name = str(entity.get("name") or "").strip().lower()
    return name


def _index(entities: Sequence[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for entity in entities:
        key = component_key(entity)
        if key:
            index.setdefault(key, entity)
    return index


def _versions_agree(left: str | None, right: str | None) -> bool:
    """Tolerant of the `v` prefix, exact otherwise.

    `v1.2.3` and `1.2.3` are the same release written by two tools. Anything
    beyond that is a real difference: vulnerability matching is version-exact,
    and treating 1.2.3 as 1.2.4 would hide the finding.
    """
    if left is None or right is None:
        return left == right
    return left.strip().lstrip("vV") == right.strip().lstrip("vV")


def compare(
    repo_entities: Sequence[dict[str, Any]],
    supplier_entities: Sequence[dict[str, Any]],
) -> GenerationDiff:
    """Component-by-component comparison of two SBOMs for one release."""
    repo_index = _index(repo_entities)
    supplier_index = _index(supplier_entities)
    diff = GenerationDiff()

    for key, repo_entity in repo_index.items():
        supplier_entity = supplier_index.get(key)
        if supplier_entity is None:
            diff.only_in_repo.append(
                ComponentRef(key, str(repo_entity.get("name")), repo_entity.get("version"))
            )
            continue

        repo_version = repo_entity.get("version")
        supplier_version = supplier_entity.get("version")
        if _versions_agree(repo_version, supplier_version):
            diff.matched += 1
        else:
            diff.version_mismatch.append(
                VersionMismatch(
                    key=key,
                    name=str(repo_entity.get("name")),
                    repo_version=repo_version,
                    supplier_version=supplier_version,
                )
            )

    for key, supplier_entity in supplier_index.items():
        if key not in repo_index:
            diff.only_in_supplier.append(
                ComponentRef(
                    key, str(supplier_entity.get("name")), supplier_entity.get("version")
                )
            )

    diff.only_in_repo.sort(key=lambda item: item.name)
    diff.only_in_supplier.sort(key=lambda item: item.name)
    diff.version_mismatch.sort(key=lambda item: item.name)
    return diff
