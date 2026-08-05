"""Parsing limits for untrusted documents.

**Every BOM this system reads is untrusted input.** It arrives from a supplier
being assessed, which is precisely the party with a motive to influence the
assessment. Three attacks matter and each has a different shape:

* **XXE.** An XML external entity reads a file off the server or opens an
  outbound connection from inside the parser. `defusedxml`-equivalent settings on
  `lxml` close it, and the settings are asserted rather than assumed — the
  default in every XML library has historically been the unsafe one.
* **Zip bombs.** A 40 KB archive expanding to 40 GB. Enforced on the
  *decompressed* size as it is read, not on the declared size, which the archive
  controls.
* **Nested JSON.** A million nested arrays exhausts the stack during parsing, in
  C, before any of our validation runs.

The limits are deliberately generous — a real 50,000-component SBOM must pass —
and the point is that a limit exists at all.
"""

from __future__ import annotations

import io
import json
import zipfile
from typing import Any

#: A 50,000-component CycloneDX document is roughly 30 MB. 200 MB leaves room
#: for a genuinely large estate and still refuses an archive bomb.
MAX_DECOMPRESSED_BYTES = 200 * 1024 * 1024
#: Compression beyond this is not a real BOM.
MAX_COMPRESSION_RATIO = 200
#: CycloneDX nests about six deep; SPDX about four. 40 is far beyond any real
#: document and far below what exhausts the parser.
MAX_JSON_DEPTH = 40


class UnsafeDocument(ValueError):
    """The document is shaped to attack the parser rather than be read."""


def parse_xml(payload: bytes) -> Any:
    """Parse XML with external entities disabled.

    An SBOM in XML is a supported CycloneDX serialisation, so this path exists —
    and it is the highest-risk parser in the system.
    """
    try:
        from lxml import etree
    except ImportError as error:  # pragma: no cover - lxml ships with python-docx
        raise UnsafeDocument("no XML parser available") from error

    # Every one of these defaults to the unsafe value somewhere in lxml's
    # history, so all four are set explicitly rather than trusted.
    parser = etree.XMLParser(
        resolve_entities=False,  # the XXE control
        no_network=True,  # no outbound fetch from inside the parser
        huge_tree=False,  # billion-laughs expansion
        dtd_validation=False,
        load_dtd=False,
    )
    try:
        return etree.fromstring(payload, parser=parser)
    except etree.XMLSyntaxError as error:
        raise UnsafeDocument(f"XML could not be parsed: {error}") from None


#: A live XXE attempt, used to prove the parser is safe by behaviour.
XXE_PROBE = (
    b'<?xml version="1.0"?>'
    b'<!DOCTYPE bom [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    b"<bom><component><name>&xxe;</name></component></bom>"
)


def assert_xml_parser_is_safe() -> None:
    """Prove the parser is safe by *behaviour*, not by introspection.

    An earlier version asserted `parser.resolve_entities is False` — an attribute
    lxml does not expose, so the check raised rather than passing and would have
    raised just as loudly on a parser that was genuinely unsafe. Running the
    attack and confirming nothing leaks tests the property that matters, and
    survives lxml changing how it stores its settings.
    """
    root = parse_xml(XXE_PROBE)
    leaked = root.findtext(".//name") or ""
    if "root:" in leaked or len(leaked) > 64:
        raise UnsafeDocument(
            "the XML parser expanded an external entity: XXE is NOT mitigated"
        )


def json_depth(value: Any, *, depth: int = 0, limit: int = MAX_JSON_DEPTH) -> int:
    """Measure nesting depth, stopping at the limit rather than recursing to it."""
    if depth > limit:
        raise UnsafeDocument(
            f"JSON nesting exceeds {limit} levels. A real BOM nests fewer than ten; "
            "deeper structures exhaust the parser stack before validation runs."
        )
    if isinstance(value, dict):
        return max(
            (json_depth(item, depth=depth + 1, limit=limit) for item in value.values()),
            default=depth,
        )
    if isinstance(value, list):
        return max(
            (json_depth(item, depth=depth + 1, limit=limit) for item in value),
            default=depth,
        )
    return depth


def loads(payload: str | bytes, *, limit: int = MAX_JSON_DEPTH) -> Any:
    """Parse JSON and refuse a document nested beyond any plausible BOM."""
    document = json.loads(payload)
    json_depth(document, limit=limit)
    return document


def extract_single_file(
    archive: bytes, *, max_bytes: int = MAX_DECOMPRESSED_BYTES
) -> bytes:
    """Read one file from a zip, bounded on the *decompressed* size.

    Bounded as it is read rather than by the declared size: the header is written
    by whoever built the archive, and a bomb declares whatever it likes.
    """
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        names = [name for name in bundle.namelist() if not name.endswith("/")]
        if len(names) != 1:
            raise UnsafeDocument(
                f"expected exactly one file in the archive, found {len(names)}"
            )

        info = bundle.getinfo(names[0])
        if info.file_size and info.compress_size:
            ratio = info.file_size / info.compress_size
            if ratio > MAX_COMPRESSION_RATIO:
                raise UnsafeDocument(
                    f"compression ratio {ratio:.0f}:1 exceeds {MAX_COMPRESSION_RATIO}:1; "
                    "this is an archive bomb rather than a BOM"
                )

        read = 0
        chunks: list[bytes] = []
        with bundle.open(info) as handle:
            while chunk := handle.read(1024 * 1024):
                read += len(chunk)
                if read > max_bytes:
                    raise UnsafeDocument(
                        f"decompressed size exceeds {max_bytes} bytes; the declared "
                        "size in the archive header is not trusted"
                    )
                chunks.append(chunk)
        return b"".join(chunks)
