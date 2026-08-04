"""The shared parse result and the conservation contract.

**parsed + rejected == entry_count, for every document, always.** This is the
rule that makes "nothing is dropped silently" checkable rather than aspirational:
a parser that quietly skips a malformed entry produces a smaller denominator,
which *raises* every coverage percentage in the assessment. Silent drops do not
merely lose information — they inflate the score.

Every parser returns this type and every parser calls `assert_conserved`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class EntryConservationError(AssertionError):
    """parsed + rejected did not equal the input entry count."""


@dataclass(frozen=True, slots=True)
class RejectedEntry:
    """One input entry that did not become a scored entity.

    `reason` is written for the supplier who has to fix it, not for us: it names
    what was wrong and, where possible, which field.
    """

    ord: int
    reason: str
    payload: Any = None
    #: Identifier if the entry had one, so a supplier can find it in their file.
    ref: str | None = None

    def as_row(self) -> dict[str, Any]:
        return {
            "ord": self.ord,
            "parse_status": "rejected",
            "reason": self.reason,
            "payload": self.payload,
            "ref": self.ref,
        }


@dataclass(slots=True)
class ParseResult:
    entities: list[dict[str, Any]] = field(default_factory=list)
    rejected: list[RejectedEntry] = field(default_factory=list)
    spec_version: str = ""
    format: str = ""
    doc_author: str | None = None
    doc_timestamp: str | None = None
    doc_name: str | None = None
    #: Entries the source document declared, counted before parsing began.
    declared_entries: int = 0

    @property
    def entry_count(self) -> int:
        return len(self.entities) + len(self.rejected)

    @property
    def parsed_count(self) -> int:
        return len(self.entities)

    @property
    def rejected_count(self) -> int:
        return len(self.rejected)

    def reject(self, ord: int, reason: str, *, payload: Any = None, ref: str | None = None) -> None:
        self.rejected.append(RejectedEntry(ord=ord, reason=reason, payload=payload, ref=ref))

    def assert_conserved(self, input_count: int | None = None) -> None:
        """Raise unless every input entry was accounted for.

        Called by the parser itself before it returns, so a conservation bug
        cannot escape the module that caused it.
        """
        expected = self.declared_entries if input_count is None else input_count
        if self.entry_count != expected:
            raise EntryConservationError(
                f"entry conservation violated: {self.parsed_count} parsed + "
                f"{self.rejected_count} rejected = {self.entry_count}, but the "
                f"document declared {expected} entries. "
                f"{abs(expected - self.entry_count)} entry/entries would have been "
                "dropped silently, which inflates every coverage percentage."
            )
