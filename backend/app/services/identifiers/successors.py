"""Rebrand and acquisition links, per Table 4.

Table 4's rationale for a supplier-based identifier is that it must survive
rebranding and acquisition. That only holds if the registry records where an
organisation went: Sun Microsystems became Oracle, and a BOM issued in 2009 still
says Sun. Without a successor chain, an identifier issued then and an identifier
issued now name the same supplier differently, which defeats the point.

Chains are walked with cycle detection, because acquisitions get recorded from
both directions and a loop would hang a lookup.
"""

from __future__ import annotations

from dataclasses import dataclass


class SuccessorCycle(RuntimeError):
    """The successor chain loops. A data error, reported rather than hung on."""


@dataclass(frozen=True, slots=True)
class Link:
    organisation: str
    successor: str | None
    note: str = ""


def resolve_current(
    organisation: str, links: dict[str, str], *, max_depth: int = 10
) -> tuple[str, list[str]]:
    """Walk to the current organisation, returning it and the chain travelled."""
    chain = [organisation]
    seen = {organisation}
    current = organisation

    for _ in range(max_depth):
        successor = links.get(current)
        if successor is None:
            return current, chain
        if successor in seen:
            raise SuccessorCycle(
                f"successor chain loops at {successor!r}: {' -> '.join(chain)} -> {successor}"
            )
        seen.add(successor)
        chain.append(successor)
        current = successor

    raise SuccessorCycle(
        f"successor chain exceeded {max_depth} hops: {' -> '.join(chain)}"
    )


def historical_names(organisation: str, links: dict[str, str]) -> list[str]:
    """Every predecessor of an organisation.

    Used when matching an old BOM: a submission naming "Sun Microsystems" must
    match a registry entry recorded under Oracle.
    """
    return sorted(name for name, successor in links.items() if successor == organisation)
