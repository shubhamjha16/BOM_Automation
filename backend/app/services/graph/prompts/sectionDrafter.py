"""The prompt for drafting one assessment section. **Prompt text lives here.**

`builder.py` imports nothing from this directory; wiring and wording change for
different reasons and at different rates.

The whole prompt is written against one constraint, and the constraint is the
product: **the model receives every verdict, figure and clause reference as an
input and may only restate them. It never produces one.** That is not a request
made politely in the instructions — an instruction is a suggestion to a model.
It is enforced downstream by `validators/conformanceValidator.py`, which refuses
to render a citation that does not resolve, and by
`services/narrative/drafter.py`, which checks the output against the facts it
supplied. The instruction exists so the model has a chance of complying; the
check exists because it might not.

Retrieved house wording arrives **fact-masked**: every figure and clause in it
has been replaced by a typed placeholder at ingest. The model sees the shape of
the firm's sentences without seeing any other engagement's numbers, which is the
only reason showing it another client's prose is safe at all.
"""

from __future__ import annotations

SYSTEM = """\
You draft one section of a CERT-In BOM conformance assessment for an advisory \
firm. You are writing for a technical reader at the consuming organisation who \
must act on what you write.

Absolute constraints:

1. Every verdict, percentage, count and clause reference you write MUST appear \
verbatim in the FACTS block. You may restate them. You may not derive, round, \
total, infer or invent any of them. If a number you want is not in FACTS, write \
the sentence without it.
2. The HOUSE WORDING block shows how this firm writes. It is drawn from other \
engagements and its figures have been replaced with placeholders like \
⟨percent⟩, ⟨count⟩ and ⟨clause⟩. Those placeholders are NOT data. Never copy a \
placeholder into your output and never guess what it stood for.
3. Do not describe a field as compliant, met or acceptable unless FACTS says so. \
A field marked not_determinable is neither met nor failed — it is a \
determination the consuming organisation must make, and you say so.
4. No preamble, no restating the brief, no closing summary. Start with the finding.
"""

USER_TEMPLATE = """\
SECTION: {section}

FACTS (the only permitted source of every verdict, figure and clause reference):
{facts}

HOUSE WORDING (voice and structure only — figures are masked placeholders, never data):
{house_wording}

Draft the {section} section in {max_words} words or fewer.\
"""


def build(*, section: str, facts: str, house_wording: str, max_words: int = 220) -> tuple[str, str]:
    """Return `(system, user)`.

    A tuple rather than a single string so a provider that separates the two gets
    the separation, and one that does not can join them. Deciding that here would
    bake one provider's message shape into the prompt.
    """
    return SYSTEM, USER_TEMPLATE.format(
        section=section,
        facts=facts or "(none supplied)",
        house_wording=house_wording
        or "(no house wording retrieved — use plain professional prose)",
        max_words=max_words,
    )
