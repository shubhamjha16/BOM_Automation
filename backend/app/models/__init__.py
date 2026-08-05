"""The model registry.

**Importing this package populates `Base.metadata` completely.** That guarantee
is the point of the file. A model module that nothing imports is invisible to
`create_all` and to Alembic autogenerate, so its table is silently never created
and the failure surfaces later as a missing relation — or, as it did here first,
as a foreign key that cannot resolve its target at metadata-build time.

Anything that touches the schema imports `app.models`, never an individual
module: `alembic/env.py`, test fixtures, and any script calling `create_all`.
New model modules are added below, and `test_models.py` asserts the registry
stays complete.
"""

from __future__ import annotations

from app.models.assessment import Assessment, AssessmentSection
from app.models.auditEvent import AuditEvent
from app.models.base import Base
from app.models.bomDocument import BomDocument
from app.models.client import Client
from app.models.corpus import CorpusChunk, CorpusDocument
from app.models.correlationFinding import CorrelationFindingRow
from app.models.engagement import Engagement
from app.models.enums import (
    BomFormat,
    DocumentStatus,
    EngagementKind,
    EngagementStatus,
    JobStatus,
    JobType,
    Role,
    Sector,
    SubmissionStatus,
)
from app.models.guideline import GuidelineVersion, MinimumElement
from app.models.job import Job, NodeRun
from app.models.knowledge import (
    Advisory,
    AgentEvidence,
    AgentRun,
    Cve,
    EolRecord,
    KevEntry,
)
from app.models.laneResult import FieldVerdictRow, LaneResult
from app.models.org import Org
from app.models.rawEntry import RawEntry
from app.models.registry import (
    IdentifierMapping,
    RegistryProposal,
    SupplierRegistryEntry,
)
from app.models.submission import Submission
from app.models.user import User
from app.models.vex import CsafAdvisory, VexStatement

__all__ = [
    "Advisory",
    "Assessment",
    "AssessmentSection",
    "AgentEvidence",
    "AgentRun",
    "AuditEvent",
    "Base",
    "BomDocument",
    "BomFormat",
    "Client",
    "Cve",
    "CsafAdvisory",
    "CorpusChunk",
    "CorpusDocument",
    "CorrelationFindingRow",
    "DocumentStatus",
    "Engagement",
    "EolRecord",
    "FieldVerdictRow",
    "GuidelineVersion",
    "IdentifierMapping",
    "LaneResult",
    "MinimumElement",
    "EngagementKind",
    "EngagementStatus",
    "Job",
    "KevEntry",
    "JobStatus",
    "JobType",
    "NodeRun",
    "Org",
    "RawEntry",
    "RegistryProposal",
    "Role",
    "Sector",
    "Submission",
    "SupplierRegistryEntry",
    "SubmissionStatus",
    "User",
    "VexStatement",
]
