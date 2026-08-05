"""The authorization matrix: every role × every resource × every action.

**Exhaustive rather than spot-checked, and that is the point.** A permission
model tested by examples grows holes at exactly the places nobody thought of. A
matrix that must be complete means adding a resource forces a decision about who
may reach it — the decision is made deliberately rather than inherited from
whatever the first endpoint happened to allow.

**Tenancy is not in this table.** No role reaches another organisation's data,
and that is enforced in the repository layer where it cannot be forgotten. This
answers the second question only: within your own tenant, may you do this?
"""

from __future__ import annotations

from enum import StrEnum
from itertools import product

from app.models.enums import Role


class Resource(StrEnum):
    SUBMISSION = "submission"
    ASSESSMENT = "assessment"
    LANE_RESULT = "lane_result"
    VEX_STATEMENT = "vex_statement"
    IDENTIFIER_MAPPING = "identifier_mapping"
    SUPPLIER_REGISTRY = "supplier_registry"
    ENGAGEMENT = "engagement"
    USER = "user"
    AUDIT_EVENT = "audit_event"
    MATURITY = "maturity"
    REPOSITORY = "repository"


class Action(StrEnum):
    READ = "read"
    LIST = "list"
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    APPROVE = "approve"
    EXPORT = "export"


#: Everything a role may do. Absence is denial — the matrix is closed, so a
#: resource or action added without a decision denies by default rather than
#: inheriting a permission nobody chose.
MATRIX: dict[Role, dict[Resource, frozenset[Action]]] = {
    Role.PARTNER: {
        Resource.SUBMISSION: frozenset(
            {
                Action.READ,
                Action.LIST,
                Action.CREATE,
                Action.UPDATE,
                Action.DELETE,
                Action.EXPORT,
            }
        ),
        Resource.ASSESSMENT: frozenset(
            {
                Action.READ,
                Action.LIST,
                Action.CREATE,
                Action.UPDATE,
                Action.APPROVE,
                Action.EXPORT,
            }
        ),
        Resource.LANE_RESULT: frozenset({Action.READ, Action.LIST, Action.EXPORT}),
        Resource.VEX_STATEMENT: frozenset(
            {
                Action.READ,
                Action.LIST,
                Action.CREATE,
                Action.UPDATE,
                Action.EXPORT,
            }
        ),
        Resource.IDENTIFIER_MAPPING: frozenset({Action.READ, Action.LIST, Action.UPDATE}),
        Resource.SUPPLIER_REGISTRY: frozenset(
            {
                Action.READ,
                Action.LIST,
                Action.CREATE,
                Action.UPDATE,
            }
        ),
        Resource.ENGAGEMENT: frozenset(
            {
                Action.READ,
                Action.LIST,
                Action.CREATE,
                Action.UPDATE,
                Action.DELETE,
            }
        ),
        Resource.USER: frozenset(
            {
                Action.READ,
                Action.LIST,
                Action.CREATE,
                Action.UPDATE,
                Action.DELETE,
            }
        ),
        Resource.AUDIT_EVENT: frozenset({Action.READ, Action.LIST}),
        Resource.MATURITY: frozenset({Action.READ, Action.LIST, Action.CREATE, Action.EXPORT}),
        Resource.REPOSITORY: frozenset({Action.READ, Action.LIST, Action.CREATE, Action.DELETE}),
    },
    Role.MANAGER: {
        Resource.SUBMISSION: frozenset(
            {
                Action.READ,
                Action.LIST,
                Action.CREATE,
                Action.UPDATE,
                Action.EXPORT,
            }
        ),
        Resource.ASSESSMENT: frozenset(
            {
                Action.READ,
                Action.LIST,
                Action.CREATE,
                Action.UPDATE,
                Action.APPROVE,
                Action.EXPORT,
            }
        ),
        Resource.LANE_RESULT: frozenset({Action.READ, Action.LIST, Action.EXPORT}),
        Resource.VEX_STATEMENT: frozenset(
            {
                Action.READ,
                Action.LIST,
                Action.CREATE,
                Action.UPDATE,
                Action.EXPORT,
            }
        ),
        Resource.IDENTIFIER_MAPPING: frozenset({Action.READ, Action.LIST, Action.UPDATE}),
        Resource.SUPPLIER_REGISTRY: frozenset(
            {
                Action.READ,
                Action.LIST,
                Action.CREATE,
                Action.UPDATE,
            }
        ),
        Resource.ENGAGEMENT: frozenset({Action.READ, Action.LIST, Action.CREATE, Action.UPDATE}),
        Resource.USER: frozenset({Action.READ, Action.LIST}),
        Resource.AUDIT_EVENT: frozenset({Action.READ, Action.LIST}),
        Resource.MATURITY: frozenset({Action.READ, Action.LIST, Action.CREATE, Action.EXPORT}),
        Resource.REPOSITORY: frozenset({Action.READ, Action.LIST, Action.CREATE}),
    },
    Role.ASSESSOR: {
        Resource.SUBMISSION: frozenset(
            {
                Action.READ,
                Action.LIST,
                Action.CREATE,
                Action.UPDATE,
                Action.EXPORT,
            }
        ),
        # Creates and edits assessments; never approves one. The separation §11
        # requires is a permission here and a distinct-person check at the gate.
        Resource.ASSESSMENT: frozenset(
            {
                Action.READ,
                Action.LIST,
                Action.CREATE,
                Action.UPDATE,
                Action.EXPORT,
            }
        ),
        Resource.LANE_RESULT: frozenset({Action.READ, Action.LIST, Action.EXPORT}),
        Resource.VEX_STATEMENT: frozenset({Action.READ, Action.LIST, Action.CREATE, Action.UPDATE}),
        Resource.IDENTIFIER_MAPPING: frozenset({Action.READ, Action.LIST, Action.UPDATE}),
        # May propose a registry entry; may not write the curated table.
        Resource.SUPPLIER_REGISTRY: frozenset({Action.READ, Action.LIST}),
        Resource.ENGAGEMENT: frozenset({Action.READ, Action.LIST}),
        Resource.USER: frozenset(),
        Resource.AUDIT_EVENT: frozenset(),
        Resource.MATURITY: frozenset({Action.READ, Action.LIST, Action.CREATE}),
        Resource.REPOSITORY: frozenset({Action.READ, Action.LIST, Action.CREATE}),
    },
    Role.READONLY: {
        Resource.SUBMISSION: frozenset({Action.READ, Action.LIST}),
        Resource.ASSESSMENT: frozenset({Action.READ, Action.LIST, Action.EXPORT}),
        Resource.LANE_RESULT: frozenset({Action.READ, Action.LIST}),
        Resource.VEX_STATEMENT: frozenset({Action.READ, Action.LIST}),
        Resource.IDENTIFIER_MAPPING: frozenset({Action.READ, Action.LIST}),
        Resource.SUPPLIER_REGISTRY: frozenset({Action.READ, Action.LIST}),
        Resource.ENGAGEMENT: frozenset({Action.READ, Action.LIST}),
        Resource.USER: frozenset(),
        Resource.AUDIT_EVENT: frozenset(),
        Resource.MATURITY: frozenset({Action.READ, Action.LIST}),
        Resource.REPOSITORY: frozenset({Action.READ, Action.LIST}),
    },
    Role.CLIENT: {
        # Narrower than readonly in reach, not only in verbs: a client is also
        # scoped to its own engagement in the repository layer (S16).
        Resource.SUBMISSION: frozenset({Action.READ, Action.LIST}),
        Resource.ASSESSMENT: frozenset({Action.READ, Action.LIST, Action.EXPORT}),
        Resource.LANE_RESULT: frozenset({Action.READ, Action.LIST}),
        Resource.VEX_STATEMENT: frozenset({Action.READ, Action.LIST}),
        Resource.IDENTIFIER_MAPPING: frozenset(),
        # A client must not read the firm's curated asset.
        Resource.SUPPLIER_REGISTRY: frozenset(),
        Resource.ENGAGEMENT: frozenset({Action.READ, Action.LIST}),
        Resource.USER: frozenset(),
        Resource.AUDIT_EVENT: frozenset(),
        Resource.MATURITY: frozenset({Action.READ, Action.LIST}),
        Resource.REPOSITORY: frozenset(),
    },
}


def may(role: Role, resource: Resource, action: Action) -> bool:
    """Closed by default: an unlisted pairing is denied."""
    return action in MATRIX.get(role, {}).get(resource, frozenset())


def missing_cells() -> list[tuple[str, str]]:
    """Role/resource pairs the matrix does not decide.

    Empty is the contract. A non-empty result means a resource was added without
    anyone deciding who may reach it, and the test fails rather than defaulting.
    """
    return [
        (str(role), str(resource))
        for role, resource in product(Role, Resource)
        if resource not in MATRIX.get(role, {})
    ]


def as_table() -> list[dict[str, object]]:
    return [
        {
            "role": str(role),
            "resource": str(resource),
            "actions": sorted(str(action) for action in MATRIX[role][resource]),
        }
        for role, resource in product(Role, Resource)
        if resource in MATRIX.get(role, {})
    ]
