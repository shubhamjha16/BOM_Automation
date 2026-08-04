"""Idempotency keys for assessment jobs.

The same document set submitted twice must return one `job_id` and execute once.
Suppliers retry uploads, browsers double-fire, and CI pipelines re-run on a
flake — without this, a re-submitted 50,000-component BOM is assessed twice and
appears as two entries in the estate view.

**What goes into the key, and why each part is load-bearing:**

* **Document checksums**, sorted — the submission *is* its documents. Sorting
  makes attachment order irrelevant, because the same five documents uploaded in
  a different order is the same submission.
* **The enabled lanes** — the same documents scored against a different lane set
  is a different assessment. An engagement that switches CBOM on must be able to
  re-assess without being handed the previous job.
* **The org id** — two tenants submitting a byte-identical public SBOM (they
  will; think `log4j-core`) must not collide into one job, which would leak the
  existence of one org's submission to the other.

Deliberately **not** included: timestamps, user id, filenames. All three would
make the key unique per attempt, which is the same as having no key at all.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable

#: How long a repeat submission is treated as the same job. Applied by the
#: caller against `jobs.created_at`; the key itself carries no time component.
DEFAULT_WINDOW_SECONDS = 3600


def idempotency_key(
    *, org_id: str, document_checksums: Iterable[str], enabled_lanes: Iterable[str]
) -> str:
    """SHA-256 over org, sorted document checksums and sorted enabled lanes.

    Returns 64 hex characters, matching `jobs.idempotency_key`'s column width.
    """
    checksums = sorted(str(checksum) for checksum in document_checksums)
    lanes = sorted(str(lane).lower() for lane in enabled_lanes)

    if not checksums:
        raise ValueError(
            "cannot derive an idempotency key for a submission with no documents; "
            "such a submission is refused before it reaches here"
        )

    # Length-prefixed and NUL-joined so no combination of field values can be
    # rearranged into another valid key. "a,b" + "c" and "a" + "b,c" must differ.
    parts = [org_id, *checksums, *lanes]
    material = b"\x00".join(f"{len(part)}:{part}".encode() for part in parts)
    return hashlib.sha256(material).hexdigest()
