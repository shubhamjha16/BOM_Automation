"""Resolving a component to its supplying organisation.

**Deterministic order, each rung with a distinct confidence.** The order is not
arbitrary — it runs from what a human verified down to what we inferred, and the
confidence is what lets the assessment distinguish "the firm stands behind this"
from "we guessed from a Java package name".

1. **Curated registry** (1.0) — a human wrote it and signed it.
2. **Declared supplier field** (0.8) — the supplier said so in their own BOM.
   Strong, but it is the supplier's claim about themselves, not verification.
3. **PURL namespace** (0.5) — inferred from `org.apache.tomcat`. Often right,
   and wrong in exactly the cases that matter: a namespace can be a personal
   account, a mirror, or a group that is not the supplying organisation.
4. **Unresolved** (0.0) — reported as 4.2(21) absent.

**Rung 4 is the one that matters.** An unresolvable component reports absent
rather than emitting a plausible-looking wrong identifier, because a CERT-In
identifier that looks official and names the wrong organisation is worse than a
gap a client can see and chase.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from app.services.agents.sufficiency import is_organisation
from app.services.identifiers.purl import Purl, normalise_organisation, to_certin, try_parse


class Source(StrEnum):
    CURATED = "curated"
    DECLARED_SUPPLIER = "declared_supplier"
    PURL_NAMESPACE = "purl_namespace"
    UNRESOLVED = "unresolved"


CONFIDENCE: dict[Source, float] = {
    Source.CURATED: 1.0,
    Source.DECLARED_SUPPLIER: 0.8,
    Source.PURL_NAMESPACE: 0.5,
    Source.UNRESOLVED: 0.0,
}

#: Namespace prefixes that carry no organisational meaning. `org.apache.tomcat`
#: yields "apache"; `com.github.someone` yields a username, which is precisely
#: what the sufficiency gate exists to refuse.
_STRIP_PREFIXES = ("org.", "com.", "io.", "net.", "dev.", "app.", "co.")
_PERSONAL_NAMESPACES = ("com.github", "io.github", "com.gitlab", "io.gitlab")


@dataclass(frozen=True, slots=True)
class Resolution:
    component: str
    purl: str | None
    supplier_org: str | None
    certin_id: str | None
    source: Source
    confidence: float
    reason: str = ""

    @property
    def is_resolved(self) -> bool:
        return self.source is not Source.UNRESOLVED and bool(self.certin_id)

    def as_row(self) -> dict[str, Any]:
        return {
            "component_name": self.component,
            "purl": self.purl,
            "certin_id": self.certin_id,
            "supplier_org": self.supplier_org,
            "source": str(self.source),
            "confidence": self.confidence,
        }


def organisation_from_namespace(purl: Purl) -> str | None:
    """Infer an organisation from a PURL namespace, or return None.

    Returns None for `com.github.*` and friends: a GitHub namespace names an
    account, and an account is not an organisation. That refusal is the
    difference between a registry and a guess.
    """
    namespace = (purl.namespace or "").strip()
    if not namespace:
        return None

    lowered = namespace.lower()
    if any(lowered.startswith(prefix) for prefix in _PERSONAL_NAMESPACES):
        return None

    candidate = lowered
    for prefix in _STRIP_PREFIXES:
        if candidate.startswith(prefix):
            candidate = candidate[len(prefix) :]
            break

    # org.apache.tomcat -> apache; @angular -> angular
    head = candidate.split(".")[0].lstrip("@")
    head = re.sub(r"[^a-z0-9\-]", "", head)
    if len(head) < 3:
        return None
    return head


def resolve(
    entity: dict[str, Any],
    *,
    registry: dict[str, str] | None = None,
) -> Resolution:
    """Resolve one component through the deterministic ladder.

    `registry` maps versionless PURL coordinates to organisation names — the
    curated table, passed in so this stays a pure function.
    """
    name = str(entity.get("name") or "")
    raw_purl = entity.get("purl")
    purl = try_parse(raw_purl if isinstance(raw_purl, str) else None)
    purl_string = purl.to_string() if purl else None

    def _build(org: str, source: Source, reason: str) -> Resolution:
        certin = (
            to_certin(purl, organisation=org)
            if purl
            else f"pkg:supplier/{normalise_organisation(org)}/{name}"
            + (f"@{entity['version']}" if entity.get("version") else "")
        )
        return Resolution(
            component=name,
            purl=purl_string,
            supplier_org=org,
            certin_id=certin,
            source=source,
            confidence=CONFIDENCE[source],
            reason=reason,
        )

    # 1. Curated registry — a human wrote it.
    if purl and registry and (org := registry.get(purl.coordinates)):
        return _build(org, Source.CURATED, "matched a curated registry entry")

    # 2. The supplier's own declaration.
    declared = entity.get("supplier_raw") or entity.get("publisher")
    if declared and str(declared).strip():
        verdict = is_organisation(str(declared))
        if verdict.sufficient:
            return _build(
                str(declared).strip(),
                Source.DECLARED_SUPPLIER,
                "the supplier declared this organisation in their own BOM",
            )
        # A declared value that is a handle is refused rather than promoted.
        return Resolution(
            component=name,
            purl=purl_string,
            supplier_org=None,
            certin_id=None,
            source=Source.UNRESOLVED,
            confidence=0.0,
            reason=f"declared supplier rejected: {verdict.reason}",
        )

    # 3. PURL namespace — inference, and marked as such.
    if purl and (inferred := organisation_from_namespace(purl)):
        return _build(
            inferred,
            Source.PURL_NAMESPACE,
            f"inferred from the PURL namespace {purl.namespace!r}; not verified",
        )

    # 4. Unresolved. Reported, never guessed.
    return Resolution(
        component=name,
        purl=purl_string,
        supplier_org=None,
        certin_id=None,
        source=Source.UNRESOLVED,
        confidence=0.0,
        reason=(
            "no curated entry, no declared supplier and no usable PURL namespace; "
            "4.2(21) is reported absent rather than emitting a plausible-looking "
            "wrong identifier"
        ),
    )


def unresolved_coordinates(resolutions: list[Resolution]) -> list[str]:
    """Distinct coordinates the agent should research — batched per product."""
    seen: dict[str, None] = {}
    for resolution in resolutions:
        if resolution.is_resolved:
            continue
        purl = try_parse(resolution.purl)
        key = purl.coordinates if purl else resolution.component.lower()
        seen.setdefault(key, None)
    return list(seen)


def summarise(resolutions: list[Resolution]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for resolution in resolutions:
        counts[str(resolution.source)] = counts.get(str(resolution.source), 0) + 1
    return {
        "total": len(resolutions),
        "by_source": counts,
        "resolved": sum(1 for item in resolutions if item.is_resolved),
    }
