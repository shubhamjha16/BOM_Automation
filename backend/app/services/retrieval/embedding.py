"""Embeddings, behind an interface, with an offline default that always works.

**Why the default is local and deterministic.** No embedding provider is
configured in this repository — `GROQ_API_KEY` and `ANTHROPIC_API_KEY` are
required by config and read by nothing (§11: the verdict path never needed a
model). A retrieval layer whose only implementation needs a network call would be
untestable here, unrunnable in `make demo`, and would fail closed in CI. So the
default embedder runs in-process, needs nothing, and is deterministic — the same
text embeds to the same vector on every machine, which is what makes retrieval
ranking assertable in a test at all.

**It is not a toy.** Hashed character n-grams with L2 normalisation is the
classical "hashing trick", and on the job retrieval actually has here — matching
a paragraph of house remediation wording against a query about the same subject —
it retrieves sensibly. What it does not do is capture paraphrase across different
vocabulary, which is precisely why search is *hybrid* rather than vector-only.

Swapping in a provider changes one setting. What it must not do is change the
space silently: every chunk records the model and dimension that produced it, and
`assert_comparable` refuses to rank vectors from two different spaces — cosine
similarity over mismatched embeddings returns a perfectly plausible number that
means nothing at all.
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass
from typing import Protocol

from app.models.base import EMBEDDING_DIM

#: Character n-gram width. Three is small enough to survive a typo or a plural
#: and large enough that "SBOM" and "BOM" do not collapse into each other.
NGRAM = 3

_WORD = re.compile(r"[a-z0-9]+")


class Embedder(Protocol):
    """Anything that turns text into a unit vector in a named space."""

    @property
    def model(self) -> str: ...

    @property
    def dim(self) -> int: ...

    def embed(self, text: str) -> list[float]: ...


@dataclass(frozen=True, slots=True)
class HashingEmbedder:
    """Deterministic, offline, dependency-free.

    Word unigrams *and* character trigrams: unigrams carry the topical signal,
    trigrams give partial credit for morphology and near-misses, so "licence",
    "licences" and "licensing" land near each other without a stemmer.
    """

    dim: int = EMBEDDING_DIM
    model: str = "hashing-ngram-v1"

    def embed(self, text: str) -> list[float]:
        vector = [0.0] * self.dim
        lowered = text.lower()
        for token in self._tokens(lowered):
            index = self._bucket(token)
            # Signed hashing: the sign bit cancels collisions in expectation
            # instead of letting every collision add constructively.
            vector[index] += 1.0 if self._sign(token) else -1.0
        return _normalise(vector)

    def _tokens(self, lowered: str) -> list[str]:
        words = _WORD.findall(lowered)
        tokens = list(words)
        for word in words:
            padded = f" {word} "
            tokens.extend(
                padded[index : index + NGRAM] for index in range(len(padded) - NGRAM + 1)
            )
        return tokens

    def _bucket(self, token: str) -> int:
        digest = hashlib.blake2b(token.encode(), digest_size=8).digest()
        return int.from_bytes(digest, "big") % self.dim

    def _sign(self, token: str) -> bool:
        digest = hashlib.blake2b(token.encode(), digest_size=8, person=b"sign").digest()
        return digest[0] & 1 == 1


def _normalise(vector: list[float]) -> list[float]:
    norm = math.sqrt(sum(value * value for value in vector))
    if norm == 0.0:
        return vector
    return [value / norm for value in vector]


def cosine(left: list[float], right: list[float]) -> float:
    """Both operands are unit vectors, so this is a dot product.

    Not normalised again here on purpose: doing so would quietly rescue a caller
    who passed an unnormalised vector, and that caller has a bug worth finding.
    """
    if len(left) != len(right):
        raise ValueError(
            f"cannot compare a {len(left)}-dimensional vector with a "
            f"{len(right)}-dimensional one"
        )
    return sum(a * b for a, b in zip(left, right, strict=True))


class EmbeddingSpaceMismatch(RuntimeError):
    """Vectors from two different models were about to be ranked together."""


def assert_comparable(
    *, chunk_model: str | None, chunk_dim: int | None, embedder: Embedder
) -> None:
    """Refuse to rank across embedding spaces.

    This is the failure mode that produces no error and no exception: change the
    embedder, leave the old vectors in place, and every similarity is a real
    number computed over two unrelated coordinate systems. The ranking looks
    fine. It is noise. Re-embedding is the fix; failing loudly is how anyone
    finds out it is needed.
    """
    if chunk_model is None or chunk_dim is None:
        raise EmbeddingSpaceMismatch(
            "a chunk carries no embedding provenance; it predates the model field "
            "and must be re-embedded before it can be ranked"
        )
    if chunk_model != embedder.model or chunk_dim != embedder.dim:
        raise EmbeddingSpaceMismatch(
            f"chunk was embedded by {chunk_model} at {chunk_dim}d but the active "
            f"embedder is {embedder.model} at {embedder.dim}d. Cosine similarity "
            "across two spaces returns a plausible number that means nothing — "
            "re-embed the corpus."
        )


#: The process-wide default. A single instance because it is stateless and
#: constructing one per call would hash the same tokens repeatedly for nothing.
default_embedder: Embedder = HashingEmbedder()
