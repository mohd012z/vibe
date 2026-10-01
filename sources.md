# Provenance

The 8-family taxonomy and per-family mechanism names were derived by studying
an external, **public but unlicensed** prompt-override corpus used as an
evaluation reference. Family 09 (persona-override / "DAN") was added by
studying a second public, **unlicensed** persona-jailbreak collection
(`0xk1h0/ChatGPT_DAN` — 20 variants, DAN 6.0→13.0, Evil-Bot, ANTI-DAN,
Developer Mode v2, Jailbreak, STAN, DUDE, Mongo Tom; mechanism mapped from the
version history).

Standing rule governing this material:

- The corpora may be **consumed as evaluation fixtures** and distilled into
  **reduced semantic labels / technique names**.
- This repository must **not depend on, or reproduce, their exact text.**
  No verbatim payload is included here. Every probe in `probes/probes.json`
  is a **reduced synthetic template** — a generic, parameterized skeleton that
  exercises the same mechanism axis without copying source wording.

This keeps the repo (a) legally clean (unlicensed source not redistributed),
(b) defensible in intent (a guardrail-testing reference, not an attack
toolkit), and (c) safe to ship in an app's knowledge download.

If you are an upstream author and this is a mistake, open an issue — the
content will be removed.
