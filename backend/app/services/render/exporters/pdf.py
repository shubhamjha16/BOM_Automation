"""PDF export via LibreOffice, per the locked stack.

**Unverified in this environment.** The specification fixes the route as
python-docx → LibreOffice → PDF, and LibreOffice is not installed on the machine
this was built on. The conversion is implemented as specified and
`is_available()` reports the truth rather than the code failing obscurely at
render time or, worse, a different renderer being substituted and the difference
going unmentioned.

A second renderer was deliberately not added. Two PDF paths means two layouts,
and an assessment that looks different depending on which machine rendered it is
a document a client cannot cite.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

#: LibreOffice ships under both names depending on platform and packaging.
BINARIES = ("soffice", "libreoffice")


class PdfUnavailable(RuntimeError):
    """LibreOffice is not installed, so DOCX cannot be converted."""


def binary() -> str | None:
    for candidate in BINARIES:
        if path := shutil.which(candidate):
            return path
    return None


def is_available() -> bool:
    return binary() is not None


def from_docx(docx_bytes: bytes, *, timeout: int = 120) -> bytes:
    """Convert a DOCX to PDF. Raises when LibreOffice is absent."""
    executable = binary()
    if executable is None:
        raise PdfUnavailable(
            "PDF export requires LibreOffice (soffice), which is not installed. "
            "The DOCX and XLSX exports are unaffected. Install LibreOffice, or "
            "export DOCX and convert it wherever you already render documents."
        )

    with tempfile.TemporaryDirectory() as workspace:
        directory = Path(workspace)
        source = directory / "assessment.docx"
        source.write_bytes(docx_bytes)

        subprocess.run(
            [
                executable,
                "--headless",
                "--convert-to",
                "pdf",
                "--outdir",
                str(directory),
                str(source),
            ],
            check=True,
            capture_output=True,
            timeout=timeout,
        )

        produced = directory / "assessment.pdf"
        if not produced.exists():  # pragma: no cover - conversion failure
            raise PdfUnavailable("LibreOffice ran but produced no PDF")
        return produced.read_bytes()
