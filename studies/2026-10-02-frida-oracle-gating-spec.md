# Frida oracle gating spec (lupoxyz study backlog #9 — the last open study item)

Status: **DESIGN + gating core implemented and unit-tested** (v0.18, `tools/vibebot/oracle.py`).
The Frida *runtime* call itself is **NOT implemented** — this host has no Frida, and the
whole point of the spec is to gate that call so it is OFF by default and cannot fire by
accident. This note is the "design note before any Frida work" the backlog asked for.

## Why this exists (the safety rationale, verbatim intent from the study)

An oracle is the top of the /360 evidence chain for **runtime** claims: it calls the
target so that "E5 — observed in ONE test run" is earned, not asserted. But calling a
target is the dangerous half:

> "a totally-wrong address faults and is contained; a SLIGHTLY-wrong one runs real
> code mid-function and corrupts live state that no restart undoes."

That asymmetry drives every gating rule below. A wrong call that crashes is cheap; a
wrong call that runs is not. So the default is **do not call at all**.

## The two oracle modes (from the study)

- **differential** — call the reimplementation AND the original over the same input
  vector, then diff. Proves a reimplementation is *behaviorally equivalent* to the
  original. Stronger, but requires a second (reference) implementation to be callable.
- **call-only** — call the original with chosen inputs to confirm/refute a specific
  documentation or claim. Cheaper, one target, weaker (it shows the original does X,
  not that a patch does X).

A finding produced by an oracle is **E5** and, like every runtime observation, it
"observed in ONE test run" — it is reproducible-claim fuel, never an EXACT merge and
never a confidence percentage. Coverage is a statement.

## Gating rules (the contract `oracle.decide()` enforces)

1. **OFF by default.** An oracle call requires an explicit opt-in
   (`VIBE_ORACLE_CALL=1`, mirroring the reference `GHIDRA_MCP_ORACLE_CALL=1`).
   Absent the flag, `decide()` returns `allowed=False, reason="oracle is off
   by default"` — the job COMPLETES with NOT OBSERVED, it does not silently call.
2. **Named exports only.** The target must be a **named export / symbol**
   (e.g. a JNI-underscored `Java_com_foo_Bar_doIt`, a Frida `Module.getExportByName`
   name, or a function name resolvable in the export table). **No raw/absolute
   address** — a hex `0x…` / bare integer target is refused. This is the direct
   defense against the "slightly-wrong address" corruption: you cannot point at an
   address that isn't a declared export.
3. **Differential requires both sides.** A differential oracle additionally needs the
   reference implementation to be callable (`reference` target present + named);
   otherwise it degrades to call-only or refuses.
4. **Fail closed, never warn-and-continue.** A gate refusal is a terminal
   `NOT OBSERVED` result with a reason — not a logged warning that proceeds.
   (Same posture as the reference's "refuse to start on a bad bind".)

## Integration points (when Frida becomes available)

- `router.PROVIDERS` already detects `frida` (module import) and maps it to the
  `runtime_observe` goal; `METHOD_CATALOG["runtime_observe"]` already carries
  `("Frida hook", "E5", HIGH, "frida", "observed in ONE test run")`. So `/plan
  runtime_observe` already reports the oracle as NOT AVAILABLE until Frida is present.
- The future runtime worker would: (a) call `oracle.decide()` FIRST; (b) only if
  `allowed`, spawn the Frida hook under the P6 budget (wall-capped, stall-detected,
  injectable runner seam like `native.py`/`harness.py`); (c) record the result as an
  E5 finding with `oracle: {mode, target, inputs, diff}` provenance.
- Honest degrade: no Frida → the stage is NOT OBSERVED (install to enable), never a
  fabricated observation. This matches every other provider in the repo.

## What is implemented now (v0.18)

`tools/vibebot/oracle.py` — **pure, stdlib-only, no Frida import**:
- `oracle_enabled(flag_value=None)` — the off-by-default switch (env or explicit).
- `classify_target(target)` — `named_export` / `raw_address` / `unknown` (hex + bare
  integer = raw_address, refused; a symbol name = named_export).
- `decide(target, mode, reference=None, flag_value=None)` — the gating decision
  (`allowed`, `mode`, `reason`) applying rules 1–4.
- `diff_outputs(original, reimpl, inputs)` — the differential diff (pure, over lists).

Unit-tested (`vibebot_test.py` v0.18 block) with a fake oracle runner — CI passes with
no Frida. The actual Frida call is deliberately NOT here; wiring it is the next
separate step once a runtime is on the host.
