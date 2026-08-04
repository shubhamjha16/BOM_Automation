# Conformance vectors

BOMs whose expected verdict was worked out **by hand against the guideline**, then
compared to what the engine produces — field by field, not just on the total.

The total is the weakest possible check. Two compensating errors give the right
percentage from the wrong verdicts, and a reader who only sees "87%" cannot tell.
So every vector states the expected verdict for **every** element it asserts, and
`test_vectors.py` fails on any single field that disagrees.

## Format

Each `*.json` file is:

```jsonc
{
  "name": "...",              // what this vector is testing
  "rationale": "...",         // why the expected result is what it is
  "lane": "sbom",
  "document": { ... },        // the BOM, inline
  "expected": {
    "verdict": "fail",
    "score": 43.9,            // optional; omitted where the point is the fields
    "fields": {               // element key -> expected verdict
      "license": "absent",
      "criticality": "not_determinable"
    },
    "coverage": {             // optional; element key -> [populated, total]
      "license": [12, 400]
    }
  }
}
```

## Provenance, stated plainly

These were derived from the encoded catalogue and the rules in §11 of the
specification — **not** signed off by a practising CERT-In assessor. That
signature is an S7/S14 exit condition the plan is explicit about, and it has not
happened. What these vectors currently prove is that the engine is
self-consistent and implements the stated rules; what they do not yet prove is
that those rules match an assessor's reading of the published PDF.

When an assessor does review them, every disagreement becomes a new vector here
and a permanent case in `test_catalogue.py`.
