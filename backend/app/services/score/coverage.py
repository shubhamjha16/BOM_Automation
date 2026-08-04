"""Coverage arithmetic. Pure functions, no I/O, no clock, no model.

Coverage is ``populated / total`` across the entity set — not a document-level
yes/no. This is the module that enforces "partial coverage is not a pass" (§11),
so every other rule in the scorer depends on it being exactly this simple.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from app.services.catalogue.types import MinimumElement


@dataclass(frozen=True, slots=True)
class Coverage:
    populated: int
    total: int

    def __post_init__(self) -> None:
        if self.total < 0 or self.populated < 0:
            raise ValueError("coverage counts cannot be negative")
        if self.populated > self.total:
            raise ValueError(
                f"populated ({self.populated}) exceeds total ({self.total}); "
                "the entity set and the probe disagree about what was scored"
            )

    @property
    def ratio(self) -> float:
        """Fraction populated, in [0, 1].

        An empty entity set scores 0.0, never 1.0. Vacuous truth is how a BOM with
        no components at all renders as fully conformant.
        """
        if self.total == 0:
            return 0.0
        return self.populated / self.total

    @property
    def percent(self) -> float:
        return round(self.ratio * 100, 2)


def measure(entities: Sequence[dict[str, Any]], element: MinimumElement) -> Coverage:
    """Count how many entities populate this element."""
    populated = sum(1 for entity in entities if element.probe(entity))
    return Coverage(populated=populated, total=len(entities))
