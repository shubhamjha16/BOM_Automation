"""The firm's own prose, retrievable — and scoped to one tenant, always.

**This is the most dangerous table in the product.** Everything else holds one
client's data and answers questions about that client. This holds the firm's past
assessments across *every* client, and its whole purpose is to surface passages
from one engagement while drafting another. A single missing scope predicate puts
one supplier's architecture disclosure into a competitor's report.

So the scope is not a convention here, it is the schema: `org_id` on both tables,
`TenantScopedRepository` for every read, and `tests/test_retrieval.py` builds a
corpus where the *best-matching* chunk for the query belongs to another org — so
a leak would surface as the top result rather than hide in a tail.

**What is stored is wording, not fact.** Chunks are fact-masked on the way in
(`services/retrieval/factGuard.py`): percentages, counts, clause references and
CVE identifiers are replaced with typed placeholders before the row is written.
A figure that never enters the corpus cannot be retrieved out of it into somebody
else's assessment, and figures come from the scoring engine regardless (§11).
"""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, Index, Integer, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, Timestamped, UuidPrimaryKey, embedding_vector, jsonb

#: What a corpus document is. Kept as a plain string rather than a database enum
#: for the same reason `vex_statements.status` is: the useful set grows with the
#: practice, and a schema migration is a poor place to discover that.
DOCUMENT_KINDS = ("past_assessment", "policy", "remediation_wording", "house_style")


class CorpusDocument(UuidPrimaryKey, Timestamped, Base):
    """One retrievable source: a past assessment, a policy, a house paragraph."""

    __tablename__ = "corpus_documents"
    __table_args__ = (Index("ix_corpus_documents_org_id_kind", "org_id", "kind"),)

    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    #: Where it came from — an assessment id, a filename, a policy reference.
    #: Carried so a reviewer can check a retrieved passage against its source.
    source_ref: Mapped[str | None] = mapped_column(String(512))
    #: The engagement it was written for, when there was one. Used to *exclude*
    #: an engagement's own prior text from its own draft where that would be
    #: circular, not to widen the scope.
    engagement_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("engagements.id", ondelete="SET NULL")
    )
    meta: Mapped[dict | None] = mapped_column(jsonb())


class CorpusChunk(UuidPrimaryKey, Timestamped, Base):
    """One retrievable passage, already fact-masked, with its embedding."""

    __tablename__ = "corpus_chunks"
    __table_args__ = (
        Index("ix_corpus_chunks_org_id_document_id", "org_id", "document_id"),
    )

    #: Denormalised from the document deliberately. The scope predicate must be
    #: applicable to the chunk query itself — requiring a join to know which
    #: tenant a chunk belongs to is exactly how a scope gets forgotten.
    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    document_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("corpus_documents.id", ondelete="CASCADE"),
        nullable=False,
    )
    ord: Mapped[int] = mapped_column(Integer, nullable=False)
    #: Fact-masked text. Never the original prose — see the module docstring.
    content: Mapped[str] = mapped_column(Text, nullable=False)
    #: Lowercased content, for the lexical half of hybrid search on SQLite.
    #: Postgres uses a GIN index over `to_tsvector` instead; both are built from
    #: this column so the two dialects rank the same text.
    content_lower: Mapped[str] = mapped_column(Text, nullable=False)
    embedding: Mapped[list[float] | None] = mapped_column(embedding_vector())
    #: The model and dimension that produced the embedding. **Recorded per chunk
    #: rather than assumed globally**: change the embedder and the old vectors
    #: live in a different space, where cosine similarity still returns a number
    #: and that number means nothing. A mismatch is detectable rather than silent.
    embedding_model: Mapped[str | None] = mapped_column(String(64))
    embedding_dim: Mapped[int | None] = mapped_column(Integer)
    #: How many masked facts this chunk carried. Non-zero is normal and healthy —
    #: it is evidence the guard ran. Zero across a whole corpus of past
    #: assessments would mean the masker silently stopped matching.
    masked_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
