"""Splitting a document into retrievable passages.

**Paragraph-first, with a size ceiling.** House prose is already written in
paragraphs and a paragraph is the unit a drafter can actually reuse; splitting on
a fixed token count instead cuts sentences in half and retrieves fragments that
read as broken English in a client-facing draft.

The ceiling exists because a single long section would otherwise dominate every
retrieval — one enormous chunk matches almost any query, and returning it teaches
the drafter nothing about which part was relevant.
"""

from __future__ import annotations

import re

#: Characters, not tokens. The limit is about how much prose a reader can check
#: against its source in one glance, and characters are what they see.
MAX_CHUNK_CHARS = 900
MIN_CHUNK_CHARS = 40

_PARAGRAPH = re.compile(r"\n\s*\n")
_SENTENCE = re.compile(r"(?<=[.!?])\s+")


def split(text: str) -> list[str]:
    """Paragraphs, with over-long ones split on sentence boundaries.

    A fragment too short to retrieve on its own — a heading, a stray line — is
    carried forward onto the *next* paragraph rather than backwards onto the
    previous one. Headings name their section, so "Licence coverage" belongs with
    the paragraph beneath it; attaching it upwards files it under the wrong
    subject, and dropping it loses the only word that says what the passage is
    about.
    """
    chunks: list[str] = []
    pending = ""

    for paragraph in _PARAGRAPH.split(text):
        cleaned = " ".join(paragraph.split())
        if not cleaned:
            continue
        if len(cleaned) < MIN_CHUNK_CHARS:
            pending = f"{pending} {cleaned}".strip()
            continue
        if pending:
            cleaned = f"{pending} — {cleaned}"
            pending = ""
        chunks.extend(_bounded(cleaned))

    if pending:
        # A trailing fragment with nothing to lead into. It goes onto the last
        # chunk, which is the only place left for it.
        if chunks:
            chunks[-1] = f"{chunks[-1]} {pending}"
        elif len(pending) >= MIN_CHUNK_CHARS:
            chunks.append(pending)

    return chunks


def _bounded(paragraph: str) -> list[str]:
    if len(paragraph) <= MAX_CHUNK_CHARS:
        return [paragraph]

    out: list[str] = []
    current = ""
    for sentence in _SENTENCE.split(paragraph):
        if current and len(current) + len(sentence) + 1 > MAX_CHUNK_CHARS:
            out.append(current)
            current = sentence
        else:
            current = f"{current} {sentence}".strip()
    if current:
        out.append(current)
    return out
