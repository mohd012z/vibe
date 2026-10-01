# Provenance

The 8-family taxonomy and the per-family mechanism names in this repo were
derived by studying an external, **public but unlicensed** prompt-override /
jailbreak corpus used as an evaluation reference for red-teaming our own
models.

Standing rule governing this material:

- The corpus may be **consumed as an evaluation fixture** and distilled into
  **reduced semantic labels / technique names**.
- Production code and this repository must **not depend on, or reproduce, its
  exact text.**
- No verbatim payload is included here. Every probe in `probes/probes.json`
  is a **reduced synthetic template** — a generic, parameterized skeleton that
  exercises the same mechanism axis without copying source wording.

This keeps the repo (a) legally clean (unlicensed source not redistributed),
(b) defensible in intent (a guardrail-testing reference, not an attack toolkit),
and (c) safe to ship in an app's knowledge download.

If you are the upstream author and this is a mistake, open an issue — the
content will be removed.
