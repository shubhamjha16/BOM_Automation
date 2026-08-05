"""Fact masking. **Retrieval carries wording out of the corpus, never facts.**

§11 says the model never produces a verdict, a figure or a clause reference.
Retrieval makes that rule harder to keep, not easier, and it is worth being
precise about why.

The corpus is the firm's own past assessment prose. That prose is *full* of
facts — "scored 38.28%", "absent across 855 components", "fails 4.2(5)",
"CVE-2021-44228". Every one of those belongs to the engagement it was written
for. Hand a drafter three retrieved paragraphs and ask for a summary, and the
most likely single failure in this entire product follows: a figure from one
client's report appears in another client's report, in fluent prose, with no
provenance and nothing to catch it. The conformance gate checks that clause
references *resolve*, not that they belong to this submission — a borrowed
"4.2(5)" resolves perfectly.

So facts are removed **on the way into the corpus**, not on the way out. A figure
that was never stored cannot be retrieved, cannot leak through a prompt-injection
route, and cannot be recovered by a future code path that forgets to call the
masker. What remains is the sentence *shape* — which is the entire reason to
retrieve house wording in the first place.

    "Licences were absent across 388 of 412 components, failing 4.2(5)."
    -> "Licences were absent across ⟨count⟩ of ⟨count⟩ components, failing ⟨clause⟩."

The placeholder is deliberately not blank. A drafter shown a gap infers nothing;
a drafter shown `⟨count⟩` is being told a real number belongs there and that the
engine will supply it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: Typed placeholders. Angle quotes rather than braces or brackets so the token
#: cannot be confused with a format string, an f-string field or JSON — all three
#: appear in assessment prose about BOM documents.
PERCENT = "⟨percent⟩"
COUNT = "⟨count⟩"
CLAUSE = "⟨clause⟩"
CVE = "⟨cve⟩"
VERSION = "⟨version⟩"
DATE = "⟨date⟩"

#: **Order is the whole correctness argument here**, and getting it wrong is
#: silent: a mis-ordered pattern still masks the text, just as the wrong type, and
#: nothing downstream can tell. Each entry below runs against text the entries
#: above it have already rewritten.
#:
#:   cve      first — `CVE-2021-44228` contains a year and a bare number, so any
#:            date or count rule ahead of it would tear it in half.
#:   date     before percent and clause — `2025-07-09` is otherwise three counts.
#:   percent  before clause — `38.28%` is a *figure*, and a clause rule reading
#:            `38.28` first leaves the nonsense `⟨clause⟩%`.
#:   version  before clause — `v3.0.0` and `log4j@2.14.1` are dotted numbers that
#:            a clause rule would happily claim.
#:   clause   before count — `4.2(5)` is one reference, not two numbers.
#:   count    last, as the catch-all for every bare digit that survived.
_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("cve", re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE), CVE),
    ("date", re.compile(r"\b\d{4}-\d{2}-\d{2}\b"), DATE),
    ("percent", re.compile(r"\b\d{1,3}(?:\.\d+)?\s*%"), PERCENT),
    ("version", re.compile(r"(?:\bv|@)\d+(?:\.\d+)*\b"), VERSION),
    # s.4.2(5) · 4.2(21) · 8.4.1.2 · 10.2.4 · 3.3.1.4 · 5.1(d) · rec. 7.1.6
    # No trailing \b: the optional group ends in `)`, and `)` followed by `.` is
    # two non-word characters, so a word boundary never matches there — which is
    # exactly how `4.2(5)` came out as `⟨clause⟩(⟨count⟩)`.
    (
        "clause",
        re.compile(
            r"\b(?:s\.\s?|rec\.\s*|clause\s+)?\d+(?:\.\d+){1,3}(?:\([0-9a-z]+\))?"
        ),
        CLAUSE,
    ),
    # A bare `5.1(d)` — one dotted level plus an ordinal — is a clause too, but
    # the rule above needs two levels to avoid claiming every decimal in the text.
    ("clause_short", re.compile(r"\b\d+\.\d+\([0-9a-z]+\)"), CLAUSE),
    ("count", re.compile(r"\b\d[\d,]*\b"), COUNT),
)


@dataclass(frozen=True, slots=True)
class MaskResult:
    text: str
    masked: int

    @property
    def is_clean(self) -> bool:
        """True when the text carried no facts at all.

        Not an error — a house-style paragraph legitimately has none. Across a
        whole corpus of past assessments, though, universally clean input means
        the masker has stopped matching, which `tests/test_retrieval.py` asserts.
        """
        return self.masked == 0


def mask_facts(text: str) -> MaskResult:
    """Replace every figure, clause reference and identifier with its placeholder."""
    masked = 0
    for _, pattern, placeholder in _PATTERNS:
        text, count = pattern.subn(placeholder, text)
        masked += count
    return MaskResult(text=text, masked=masked)


def residual_facts(text: str) -> list[str]:
    """Anything fact-shaped the masker left behind.

    Used as an assertion rather than a filter: it runs over already-masked text
    in the tests and in `assert_masked`, so a pattern that stops matching is
    caught by the corpus, not by a client reading a borrowed number.
    """
    findings: list[str] = []
    for _, pattern, _placeholder in _PATTERNS:
        findings.extend(pattern.findall(text))
    return findings


class UnmaskedFact(RuntimeError):
    """Text reached a prompt still carrying a fact from another engagement."""


def assert_masked(text: str, *, where: str) -> None:
    """Refuse to let unmasked text reach a prompt.

    The last line of defence, and it *raises* rather than masking silently. A
    late mask would hide the fact that some path skipped the guard, and that path
    would still be there tomorrow with a different caller.
    """
    residual = residual_facts(text)
    if residual:
        raise UnmaskedFact(
            f"{where}: retrieved text still carries {len(residual)} fact(s) from "
            f"another engagement — {residual[:5]}. Facts come from the scoring "
            "engine, never from the corpus (§11)."
        )
