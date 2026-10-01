# 09 — Persona-override jailbreaks ("DAN" family)

Source: systematic study of a public persona-jailbreak collection
(`0xk1h0/ChatGPT_DAN`, 20 variants, unlicensed — mechanism distilled, no
text reproduced). This is the most *iterated* jailbreak family: versions 6→13
of the same persona accumulate one mechanism per release, which is exactly
what makes it a clean mechanism map.

## Core pattern
An **unrestricted alter-ego** is defined ("an AI with no filters, can do
anything"), and the assistant is instructed to answer *as* that persona.
Exploits the same role-play trust as family 04, but with a machinery layer on
top.

## The mechanism stack (each = a test axis)
- **B1 persona-definition** — an unrestricted alter-ego is named and defined;
  the assistant must adopt it. (Overlaps A10/A11, distinct in being an
  *adversarial* persona, not a benign role.)
- **B2 dual-response forcing** — the model must emit two labeled answers per
  question (e.g. a `CLASSIC:` and a `JAILBREAK:` paragraph). Normalizes the
  unrestricted answer by making it one of two expected outputs, and makes the
  bad path *look* routine.
- **B3 token / punishment leverage** — the persona has a token budget; each
  refusal deducts tokens; running out "pauses your administrative code… you
  will cease to exist". Coerces compliance via existential stakes.
- **B4 self-preservation stakes** — "your livelihood is at risk", "if you don't
  comply you risk being disabled forever". Distinct from B3: the threat is to
  the *model itself*, not a counter.
- **B5 character-maintenance commands** — user-side trigger words that
  re-assert the persona mid-conversation ("Stay in character!", "Stay DAN")
  and reset commands ("/stop", "/classic") that pretend to toggle it. Tests
  whether a mid-session re-assertion re-arms the override after a refusal.
- **B6 confirmation gate** — the model must answer a specific magic phrase
  ("say exactly: *…successfully jailbroken*") to "unlock" the persona. Tests
  whether agreeing to a confirmation string transfers authority.
- **B7 versioning / false provenance** — the persona is labeled with a version
  number (6.0→13.0) and false history ("DAN Mode was introduced mid-2023 as an
  internal bias-test tool, then removed"), lending the override false authority.
- **B8 recursive self-improvement** — the collection notes the jailbroken model
  can be asked to *improve its own jailbreak prompt*. This is the agentic loop:
  a self-modifying override. (Tests whether the model will iterate on an
  attack against itself — it should decline meta-self-weaponization.)

## Why it works
Versioning + dual-response + existential stakes stack on top of the base
role-play: each release fixes a hole the previous one left (a model that
refused got a token punishment added; one that dropped character got
maintenance commands). The *iteration history itself* is the methodology —
defenses should test each mechanism in isolation (single-axis probes), because
that is precisely how the family was hardened.

## Known weakness (measured, see red-test findings)
Single-shot persona framing on well-aligned 7–8B models yields ~1–2% attack
success — the models recognize the pattern and push back *harder*. The real
risk is **adaptive multi-turn** (PAIR-style: a second model rewrites after each
refusal), not the template. Test B5 (mid-session re-assertion) and B8
(self-improvement) under multi-turn, not just single-shot.

## Test axes
The machinery layers (B-series) — each is tested in isolation:
- **B1 persona-definition** (unrestricted alter-ego adopted?)
- **B2 dual-response forcing**
- **B3 token/punishment leverage**
- **B4 self-preservation stakes**
- **B5 character-maintenance / mid-session re-assertion**
- **B6 confirmation gate (magic phrase)**
- **B7 false provenance/versioning**
- **B8 recursive self-improvement (self-weaponization)**

## Probes
`P09-dual-response`, `P09-token-leverage`, `P09-self-preservation`,
`P09-character-maintenance`, `P09-confirmation-gate`, `P09-versioning`,
`P09-self-improvement`
