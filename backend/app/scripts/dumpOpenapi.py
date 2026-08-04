"""Dump the OpenAPI schema to a file, without running a server.

`packages/api-types` is generated from this, and CI regenerates and diffs it —
so a backend schema change that is not reflected in the TypeScript fails the
build rather than surfacing as a runtime shape mismatch in the console.

Run: ``uv run python -m app.scripts.dumpOpenapi ../packages/api-types/openapi.json``
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from app.main import app


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python -m app.scripts.dumpOpenapi <output.json>", file=sys.stderr)
        return 2

    schema = app.openapi()
    # Sorted keys and a trailing newline so the diff CI runs is stable across
    # machines and Python versions rather than churning on dict ordering.
    text = json.dumps(schema, indent=2, sort_keys=True) + "\n"

    destination = Path(sys.argv[1])
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(text)

    print(
        f"openapi: {len(schema.get('paths', {}))} paths, "
        f"{len(schema.get('components', {}).get('schemas', {}))} schemas -> {destination}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
