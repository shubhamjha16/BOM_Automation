"""Error response bodies.

One shape for every refusal, so the console can render a violation list without
special-casing the endpoint that produced it.
"""

from __future__ import annotations

from pydantic import BaseModel


class ViolationOut(BaseModel):
    field: str
    message: str


class ValidationErrorOut(BaseModel):
    detail: str
    violations: list[ViolationOut]
