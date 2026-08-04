"""What a submission must satisfy before anything is persisted or enqueued.

The rule this file exists for: **a submission with zero BOM documents is refused,
not assessed.** Five `lane_absent` results and an overall score of zero reads as
an assessment of a supplier who submitted something wrong. It is an assessment of
nothing at all, and issuing one would be worse than issuing none.

Raises `SubmissionInvalid`, which the controller maps to 422. Validation lives
here rather than in the Pydantic schema because these are business rules — lane
enablement, size policy, format support — that reference configuration, and a
schema that reaches into settings stops being a description of the wire format.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.configs.envConfig import ALL_LANES, settings
from app.configs.jobTypes import ALL_JOB_TYPES, JobType
from app.services.ingest.parsers.cyclonedx import SUPPORTED_SPEC_VERSIONS


@dataclass(frozen=True, slots=True)
class Violation:
    field: str
    message: str


class SubmissionInvalid(ValueError):
    """One or more submission rules were broken.

    Carries every violation rather than the first: a supplier fixing an upload
    one error at a time, across a 100 MB document, is a bad afternoon.
    """

    def __init__(self, violations: list[Violation]) -> None:
        self.violations = violations
        super().__init__("; ".join(f"{v.field}: {v.message}" for v in violations))


def max_document_bytes() -> int:
    return settings.MAX_BOM_MB * 1024 * 1024


def validate_job_type(raw: str) -> JobType:
    try:
        job_type = JobType(raw)
    except ValueError:
        raise SubmissionInvalid(
            [
                Violation(
                    "job_type",
                    f"{raw!r} is not a known job type; valid types are "
                    f"{sorted(str(item) for item in ALL_JOB_TYPES)}",
                )
            ]
        ) from None
    return job_type


def validate_documents(documents: list[dict]) -> None:
    """Every rule that applies to the document set as a whole and one by one."""
    violations: list[Violation] = []

    # At least one lane document present — the rule this module exists for.
    if not documents:
        violations.append(
            Violation(
                "documents",
                "a submission must carry at least one BOM document; refusing to "
                "produce an assessment of an empty submission (rec. 7.1.2)",
            )
        )

    cap = max_document_bytes()
    seen_checksums: dict[str, int] = {}

    for index, document in enumerate(documents):
        field = f"documents[{index}]"

        lane = str(document.get("lane", "")).lower()
        if lane not in ALL_LANES:
            violations.append(
                Violation(
                    f"{field}.lane",
                    f"{lane!r} is not a lane; valid lanes are {list(ALL_LANES)}",
                )
            )
        elif lane not in settings.enabled_lanes:
            violations.append(
                Violation(
                    f"{field}.lane",
                    f"the {lane} lane is disabled on this deployment; the document "
                    "would be stored and never scored",
                )
            )

        size = int(document.get("size_bytes") or 0)
        if size > cap:
            violations.append(
                Violation(
                    f"{field}.size_bytes",
                    f"{size} bytes exceeds MAX_BOM_MB={settings.MAX_BOM_MB} ({cap} bytes)",
                )
            )

        spec_version = document.get("spec_version")
        if (
            document.get("format") == "CycloneDX"
            and spec_version
            and spec_version not in SUPPORTED_SPEC_VERSIONS
        ):
            violations.append(
                Violation(
                    f"{field}.spec_version",
                    f"CycloneDX {spec_version} is not supported; supported versions "
                    f"are {sorted(SUPPORTED_SPEC_VERSIONS)}",
                )
            )

        # Identical bytes twice in one submission is a mistake, not a resubmission.
        if checksum := document.get("checksum"):
            if (first := seen_checksums.get(checksum)) is not None:
                violations.append(
                    Violation(
                        f"{field}.checksum",
                        f"duplicates documents[{first}]; the same document was "
                        "attached twice",
                    )
                )
            else:
                seen_checksums[str(checksum)] = index

    if violations:
        raise SubmissionInvalid(violations)


def validate_submission(
    *, engagement_id: str | None, documents: list[dict], job_type: str | None = None
) -> None:
    """Full submission validation. Reports every violation at once."""
    violations: list[Violation] = []

    if not engagement_id:
        violations.append(
            Violation(
                "engagement_id",
                "required; a submission outside an engagement has no client, no "
                "enabled lanes and no one to report to",
            )
        )

    if job_type is not None:
        try:
            validate_job_type(job_type)
        except SubmissionInvalid as error:
            violations.extend(error.violations)

    try:
        validate_documents(documents)
    except SubmissionInvalid as error:
        violations.extend(error.violations)

    if violations:
        raise SubmissionInvalid(violations)
