"""The conformance status check posted onto a pull request.

**The point is that it is visible without leaving GitHub.** A developer who has
to open another tool to find out why their build is unhappy will not open it. So
the check body carries the score, the failing clauses and the offending
components inline, and links out only for the full assessment.

Building the payload is separated from posting it, because the payload is
testable and the posting needs credentials this environment does not have.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.services.ci.policy import GateMode, GatePolicy

MAX_LISTED_COMPONENTS = 10


@dataclass(frozen=True, slots=True)
class CheckRun:
    name: str
    status: str
    conclusion: str
    title: str
    summary: str
    text: str

    def as_payload(self) -> dict[str, Any]:
        """The GitHub check-runs API shape."""
        return {
            "name": self.name,
            "status": self.status,
            "conclusion": self.conclusion,
            "output": {"title": self.title, "summary": self.summary, "text": self.text},
        }


def _failing_rows(lane_results: list[Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for lane in lane_results:
        for row in getattr(lane, "field_results", None) or []:
            if str(row.get("verdict")) == "absent":
                rows.append({**row, "lane": lane.lane})
    return sorted(
        rows,
        key=lambda row: (
            {"critical": 0, "standard": 1, "contextual": 2}.get(str(row.get("tier")), 3),
            str(row.get("clause")),
        ),
    )


def build(
    *,
    overall_score: float | None,
    lane_results: list[Any],
    policy: GatePolicy,
    assessment_url: str | None = None,
    offending_components: dict[str, list[str]] | None = None,
) -> CheckRun:
    """Compose the check a developer sees on their pull request."""
    failing = _failing_rows(lane_results)
    critical = [
        f"{row['clause']} {row.get('label') or row['element_key']}"
        for row in failing
        if str(row.get("tier")) == "critical" and not row.get("populated")
    ]
    passed, summary = policy.decide(
        score=overall_score,
        critical_gaps=critical,
        failing_clauses=[str(row["clause"]) for row in failing],
    )

    lines: list[str] = []
    for lane in lane_results:
        score = f"{lane.score}%" if lane.score is not None else "—"
        lines.append(f"- **{lane.lane.upper()}** {score} · {lane.verdict}")

    if failing:
        lines.append("")
        lines.append("### Unmet minimum elements")
        for row in failing[:MAX_LISTED_COMPONENTS]:
            lines.append(
                f"- `{row['clause']}` {row.get('label') or row['element_key']} "
                f"({row['lane'].upper()}) — declared on {row.get('populated')} of "
                f"{row.get('total')}"
            )
            # The offending component, named inline: "which dependency?" is the
            # first question and it should not require another tool to answer.
            for component in (offending_components or {}).get(str(row["element_key"]), [])[:3]:
                lines.append(f"    - `{component}`")
        if len(failing) > MAX_LISTED_COMPONENTS:
            lines.append(f"- …and {len(failing) - MAX_LISTED_COMPONENTS} more")

    if policy.mode is GateMode.WARN:
        lines.append("")
        lines.append(
            "_This check is in **warn** mode: findings are reported and the build is "
            "not blocked. Blocking is a per-engagement policy decision._"
        )
    if assessment_url:
        lines.append("")
        lines.append(f"[Full conformance assessment]({assessment_url})")

    return CheckRun(
        name="CERT-In conformance",
        status="completed",
        conclusion="success" if passed else "failure",
        title=(
            f"{overall_score}% conformance" if overall_score is not None else "not scored"
        ),
        summary=summary,
        text="\n".join(lines),
    )
