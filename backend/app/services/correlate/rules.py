"""Cross-BOM correlation rules, as data.

**What the join buys.** Each rule compares one lane's declarations against
another's, producing a class of finding no single-lane tool can reach: not "this
field is missing" but "these two documents disagree about what this system
contains".

Every rule declares the lanes it needs. A rule whose inputs are not present does
not fire — and this is the rule that matters most in §11: **a single-lane
submission produces zero correlation findings rather than false positives.**
Correlation with nothing to correlate against is invention. A submission with
only an SBOM has not failed to declare its cryptography; it has not been asked to.

Clause references live here beside the rule, so a finding cites the guideline the
same way a field verdict does and passes the same conformance gate (S8).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from app.configs.envConfig import Lane


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class Finding:
    """One correlation finding, carrying its own clause reference."""

    rule_key: str
    severity: Severity
    clause: str
    detail: str
    #: What was found on each side, so a reader can check the claim.
    left_ref: str | None = None
    right_ref: str | None = None


#: A rule body reads the entities of each participating lane and yields findings.
RuleBody = Callable[[Mapping[str, Sequence[dict[str, Any]]]], list[Finding]]


@dataclass(frozen=True, slots=True)
class Rule:
    key: str
    label: str
    clause: str
    severity: Severity
    #: Lanes whose *content* the rule reads. Every one must have carried entities
    #: or the rule does not run.
    requires: tuple[Lane, ...]
    body: RuleBody
    #: Why this correlation is worth raising at all.
    rationale: str = ""
    #: False until the lanes it needs are implemented; reported, never silent.
    implemented: bool = True

    def applicable(self, available: set[str]) -> bool:
        return self.implemented and set(self.requires) <= available
