"""PURL parsing, and the CERT-In unique identifier of Table 3.

**Why this module is the hard part of the product.** Table 3 mandates

    pkg:supplier/OrganizationName/Component@Version

and `supplier` **is not a registered PURL type**. No generator emits it — Syft,
Trivy and cdxgen all produce an *ecosystem* type (`pkg:npm`, `pkg:maven`,
`pkg:pypi`) because that is what the package manager knows. Converting requires
resolving each package to its *supplying organisation*, which is a curated
dataset that does not exist anywhere. That is why 4.2(21) scores absent on every
real-world BOM until a registry is built, and why S11 is where the product's
moat is.

This module does the mechanical half — parse, build, round-trip. It never
invents an organisation: `to_certin` requires one to be supplied, because a
plausible-looking wrong identifier is worse than a reported absence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import quote, unquote

#: pkg:type/namespace/name@version?qualifiers#subpath — the PURL grammar.
_PURL = re.compile(
    r"^pkg:(?P<type>[^/]+)/(?P<rest>[^?#]+?)(?:@(?P<version>[^?#]+))?(?:\?(?P<qualifiers>[^#]*))?(?:#(?P<subpath>.*))?$"
)

CERTIN_TYPE = "supplier"


class InvalidPurl(ValueError):
    """The string is not a package URL."""


@dataclass(frozen=True, slots=True)
class Purl:
    type: str
    name: str
    namespace: str | None = None
    version: str | None = None
    qualifiers: dict[str, str] | None = None
    subpath: str | None = None

    def __str__(self) -> str:
        return self.to_string()

    def to_string(self) -> str:
        parts = [f"pkg:{self.type}"]
        if self.namespace:
            # Namespace segments are individually encoded; the separator is not.
            parts.append(
                "/" + "/".join(quote(segment, safe="") for segment in self.namespace.split("/"))
            )
        parts.append("/" + quote(self.name, safe=""))
        if self.version:
            parts.append("@" + quote(self.version, safe=""))
        if self.qualifiers:
            encoded = "&".join(
                f"{key}={quote(value, safe='')}" for key, value in sorted(self.qualifiers.items())
            )
            parts.append("?" + encoded)
        if self.subpath:
            parts.append("#" + self.subpath)
        return "".join(parts)

    @property
    def coordinates(self) -> str:
        """type/namespace/name, without a version. The registry's lookup key.

        Versionless because supplier identity belongs to the *product*: Tomcat
        9.0.71 and 10.1.0 are supplied by the same foundation, and keying the
        registry per version would multiply a curated dataset by every release.
        """
        return (
            f"{self.type}/{self.namespace}/{self.name}"
            if self.namespace
            else f"{self.type}/{self.name}"
        )


def parse(value: str) -> Purl:
    """Parse a PURL. Raises rather than returning a partial result."""
    if not isinstance(value, str) or not value.strip():
        raise InvalidPurl("empty package URL")

    match = _PURL.match(value.strip())
    if match is None:
        raise InvalidPurl(f"{value!r} is not a package URL (expected pkg:type/name@version)")

    rest = match.group("rest").strip("/")
    segments = [unquote(segment) for segment in rest.split("/") if segment]
    if not segments:
        raise InvalidPurl(f"{value!r} carries no component name")

    name = segments[-1]
    namespace = "/".join(segments[:-1]) or None

    qualifiers: dict[str, str] | None = None
    if raw := match.group("qualifiers"):
        qualifiers = {}
        for pair in raw.split("&"):
            if "=" in pair:
                key, _, val = pair.partition("=")
                qualifiers[key] = unquote(val)

    return Purl(
        # PURL types are case-insensitive and canonically lowercase.
        type=match.group("type").lower(),
        namespace=namespace,
        name=name,
        version=unquote(match.group("version")) if match.group("version") else None,
        qualifiers=qualifiers or None,
        subpath=match.group("subpath") or None,
    )


def try_parse(value: str | None) -> Purl | None:
    """Parse, or None. For the many places a component has no usable PURL."""
    if not value:
        return None
    try:
        return parse(value)
    except InvalidPurl:
        return None


def normalise_organisation(name: str) -> str:
    """Organisation name → the form Table 3's worked example uses.

    "Apache Software Foundation" becomes "ApacheSoftwareFoundation": the example
    in the guideline is PascalCase with separators removed. Punctuation that
    carries no identity — commas, full stops, "Inc." — is dropped so that two
    spellings of one organisation do not become two identifiers.
    """
    if not name or not name.strip():
        raise ValueError("an organisation name is required to build a CERT-In identifier")

    cleaned = re.sub(r"[^A-Za-z0-9\s\-&]", " ", name)
    words = [word for word in re.split(r"[\s\-&]+", cleaned) if word]
    if not words:
        raise ValueError(f"{name!r} contains no usable characters for an identifier")

    return "".join(word[:1].upper() + word[1:] if word[:1].islower() else word for word in words)


def to_certin(purl: Purl | str, *, organisation: str) -> str:
    """Build the Table 3 identifier: pkg:supplier/OrganizationName/Component@Version.

    `organisation` is required and has no default. There is no inference here on
    purpose — resolving it is the registry's job (S11), and a fallback would
    silently emit a confident wrong identifier for every unresolved component.
    """
    parsed = parse(purl) if isinstance(purl, str) else purl
    return Purl(
        type=CERTIN_TYPE,
        namespace=normalise_organisation(organisation),
        name=parsed.name,
        version=parsed.version,
    ).to_string()


def is_certin(value: str) -> bool:
    parsed = try_parse(value)
    return parsed is not None and parsed.type == CERTIN_TYPE and bool(parsed.namespace)
