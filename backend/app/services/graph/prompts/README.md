# Prompts are data

One module per node that talks to a model. `builder.py` contains zero prompt text
and imports nothing from this directory — wiring and wording change for different
reasons and at different rates.

Nodes that will land here:

| Module | Node | Sprint |
|---|---|---|
| `narrativeStructure.py` | plans the assessment's sections | S15 |
| `sectionDrafter.py` | drafts prose for one section | **landed** |
| `narrativeCritic.py` | critiques a draft, bounded at 2 rounds | S15 |
| `vexDrafter.py` | drafts a VEX justification, never a status | S12 |
| `healer.py` | repairs what the critic flagged | S15 |

**Every prompt in this directory is written against one constraint:** the model
receives verdicts, figures and clause references as *inputs* and may only
restate them. It never produces one. That is enforced in code by
`validators/figureProvenanceValidator.py` (S11) and
`validators/conformanceValidator.py` (S8) — a prompt instruction is not an
enforcement mechanism, and these prompts are written as though the validators
did not exist, then the validators are written as though the prompts did not.
