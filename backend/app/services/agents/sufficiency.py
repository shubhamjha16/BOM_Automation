"""The sufficiency gate — what makes a loop agentic rather than a search box.

A retrieval loop without this returns the first plausible result. The gate asks a
different question: *does what I found actually support a determination, or does
it merely mention the thing I searched for?*

The two gates here answer that for the two S10/S11 questions:

* **Lifecycle** — is this an end-of-life date for *this product*, or a date on a
  page that happens to mention it?
* **Supplier** — is this an organisation, or a GitHub handle, a maintainer's
  personal account, or a mirror? This one is the whole point of S11, and it is
  the check that stops "someone's username" becoming a CERT-In supplier
  identifier that ships to a client.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.services.agents.evidence import Evidence


@dataclass(frozen=True, slots=True)
class Sufficiency:
    sufficient: bool
    confidence: float
    reason: str
    #: What to search instead, when insufficient. A re-query from the same angle
    #: returns the same answer, so an unusable hint means stopping.
    next_angle: str | None = None


# --- supplier resolution ----------------------------------------------------

#: Signals that a string is a person or a handle, not an organisation.
PERSONAL_MARKERS = (
    "github.com/",
    "gitlab.com/",
    "@gmail.",
    "@outlook.",
    "@yahoo.",
    "personal",
    "maintainer",
    "individual",
)

#: Signals that a string names an organisation.
ORGANISATION_MARKERS = (
    "foundation",
    "software foundation",
    "inc",
    "inc.",
    "llc",
    "ltd",
    "limited",
    "gmbh",
    "corporation",
    "corp",
    "company",
    "institute",
    "consortium",
    "project",
    "association",
    "university",
    "labs",
    "technologies",
    "systems",
)

#: A mirror or a redistributor is not the supplying organisation.
MIRROR_MARKERS = ("mirror", "fork of", "unofficial", "redistribution", "repackage")

_HANDLE = re.compile(r"^[a-z0-9][a-z0-9\-_]{0,38}$")


def is_organisation(candidate: str) -> Sufficiency:
    """Is this an organisation name, or a handle?

    Table 3 builds the CERT-In identifier from an *OrganizationName*. Publishing
    a maintainer's username there produces an identifier that looks official,
    survives review, and is wrong — so the burden of proof sits on the candidate.
    """
    if not candidate or not candidate.strip():
        return Sufficiency(False, 0.0, "no candidate supplier was found", next_angle=None)

    value = candidate.strip()
    lowered = value.lower()

    if any(marker in lowered for marker in MIRROR_MARKERS):
        return Sufficiency(
            False,
            0.0,
            f"{value!r} describes a mirror or fork, not the supplying organisation",
            next_angle="the upstream project's own governance or about page",
        )

    if any(marker in lowered for marker in PERSONAL_MARKERS):
        return Sufficiency(
            False,
            0.0,
            f"{value!r} looks like a personal account or handle, not an organisation",
            next_angle="the project's governance, foundation or trademark page",
        )

    if any(marker in lowered.split() or marker in lowered for marker in ORGANISATION_MARKERS):
        return Sufficiency(True, 0.85, f"{value!r} carries an organisational marker")

    # A bare lowercase token with no spaces is a username far more often than a
    # company. Refused rather than published, and re-queried from another angle.
    if _HANDLE.match(lowered) and " " not in value:
        return Sufficiency(
            False,
            0.25,
            f"{value!r} is a bare handle with no organisational marker; it may be a "
            "username, and a username must not become a CERT-In supplier identifier",
            next_angle="the project's governance page or its package registry owner",
        )

    if len(value.split()) >= 2:
        # Multi-word proper noun with no marker: plausible, but not certain.
        return Sufficiency(
            True, 0.6, f"{value!r} reads as a multi-word organisation name"
        )

    return Sufficiency(
        False,
        0.2,
        f"{value!r} is a single token with no organisational marker",
        next_angle="the project's governance or trademark page",
    )


# --- lifecycle resolution ---------------------------------------------------

_DATE = re.compile(r"\b(20\d{2})-(\d{2})-(\d{2})\b")


def supports_lifecycle(product: str, snippet: str) -> Sufficiency:
    """Does this text state an end-of-life date *for this product*?"""
    if not snippet.strip():
        return Sufficiency(False, 0.0, "nothing was retrieved", next_angle=None)

    lowered = snippet.lower()
    mentions_product = product.split("/")[-1].lower() in lowered
    has_date = bool(_DATE.search(snippet))
    has_lifecycle_language = any(
        phrase in lowered
        for phrase in ("end of life", "end-of-life", "eol", "supported until", "sunset")
    )

    if not mentions_product:
        return Sufficiency(
            False,
            0.0,
            f"the retrieved text does not mention {product!r}",
            next_angle=f"the vendor's own lifecycle page for {product}",
        )
    if not has_date:
        return Sufficiency(
            False,
            0.2,
            "the text mentions the product but states no date",
            next_angle=f"{product} release or support schedule",
        )
    if not has_lifecycle_language:
        # A date near a product name is not an EOL date. This is the exact
        # failure a search box makes and a sufficiency gate exists to prevent.
        return Sufficiency(
            False,
            0.3,
            "a date was found but nothing marks it as an end-of-life date",
            next_angle=f"{product} end-of-life announcement",
        )

    return Sufficiency(True, 0.75, "the text states an end-of-life date for this product")


def evidence_from(
    hop: int, query: str, url: str | None, snippet: str, gate: Sufficiency
) -> Evidence:
    return Evidence(
        hop=hop,
        query=query,
        source_url=url,
        snippet=snippet[:500],
        supports=gate.sufficient,
        confidence=gate.confidence,
    )
