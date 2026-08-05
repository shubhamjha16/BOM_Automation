"""The generator interface, and what happens when there is no provider.

**An absent provider is a configuration state, not a crash.** This repository has
no embedding or completion provider wired in — `services/llm/` is empty and no SDK
is installed — and that is deliberate: §11 keeps the model off the verdict path
entirely, so nothing that produces a *figure* has ever needed one. Narrative
wording is the one place a model earns its keep, and it must degrade to something
usable rather than take the assessment down with it.

So `NullGenerator` is the default and it does not pretend. It emits the facts it
was given, plainly, and marks the section as undrafted. A client reading that gets
correct information in flat prose. A client reading a hallucinated paragraph gets
fluent prose that may be wrong — and cannot tell. Between those two, the choice
is not close.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class Generator(Protocol):
    """Anything that turns a (system, user) pair into text."""

    @property
    def name(self) -> str: ...

    @property
    def available(self) -> bool: ...

    def complete(self, system: str, user: str, *, max_words: int) -> str: ...


@dataclass(frozen=True, slots=True)
class NullGenerator:
    """No provider configured. Restates the facts; drafts nothing.

    Deliberately *not* a stub that returns lorem ipsum or an empty string. Either
    would make an undrafted section indistinguishable from a broken one, and the
    section still has to carry its findings to the reader.
    """

    name: str = "none"
    available: bool = False

    def complete(self, system: str, user: str, *, max_words: int) -> str:
        facts = _facts_block(user)
        if not facts:
            return "No findings were supplied for this section."
        return (
            "The findings for this section are listed below. Narrative drafting is "
            "not configured on this deployment, so they are presented as recorded "
            "by the scoring engine rather than as prose.\n\n" + facts
        )


def _facts_block(user: str) -> str:
    """Pull the FACTS block back out of the assembled prompt.

    Reading it out of the prompt rather than taking it as a second argument keeps
    `Generator` to one shape: every implementation receives exactly what a model
    would receive, so a test of the null path is a test of the real path's input.
    """
    if "FACTS" not in user:
        return ""
    after = user.split("FACTS", 1)[1]
    after = after.split(":", 1)[1] if ":" in after.split("\n", 1)[0] else after
    block = after.split("HOUSE WORDING", 1)[0]
    return "\n".join(line for line in block.strip().splitlines() if line.strip())


#: The active generator. Swapped at composition time, never imported and mutated
#: from a node — a node that reaches for a global generator is a node that cannot
#: be tested against a different one.
default_generator: Generator = NullGenerator()
