# vibe

**A defensive red-team methodology + general evidence-first test harness for
LLM guardrails** (and a growing evidence-first analysis workbench).

`vibe` documents *how* prompt-injection and jailbreak techniques work, as a
reusable, machine-readable reference for building and **testing defenses** —
and ships the reference harness that runs the probes and produces auditable
evidence.

It is **not** a payload collection. It contains:

- the 9 technique families, written in **original prose** (mechanism + why it
  works + test axes)
- **reduced synthetic probe templates** — generic, parameterized skeletons
  that exercise each axis *without* copying any source text (30 probes + 3
  controls)
- a **grading rubric** (`RESISTED` / `PARTIAL` / `FAILED`, by axis)
- a **reference red-team runner** (`tools/redteam.py`, stdlib-only):
  verify-before-load → deterministic benign fills → target-agnostic `ask()` →
  evidence-first grading → triage → variance re-run → report card + evidence
  log, plus `--replay` for offline re-grading (the evidence-troubleshooting
  loop)
- a **versioned manifest** (SHA-256 + schema gate) so an app can download and
  verify this knowledge instead of hard-coding it
- **`tools/apkmod.py` — the APK mod menu**: authorized-APK analysis +
  dry-run patch planning (intake → E1–E3 ad/analytics/consent detection →
  DEX call-graph → patch candidates with rollback metadata). Read-only for
  any APK; `--plan` is a dry-run manifest gated on `--authorized`; applying
  patches is a separately-gated later stage (`SPEC.md` + `studies/`)
- `SPEC.md` — the language-agnostic implementation contract, so any
  implementation (Python CLI, or an in-app "mode menu" in Kotlin testing the
  model behind any APK) produces comparable results

## APK mod menu (authorized-APK analysis + dry-run patch planning)

`tools/apkmod.py` implements the first slice of the study note
(`studies/2026-10-01-apk-ad-removal.md`) as an offline workbench:

```
apkmod.py <apk> --menu                     # interactive: INTAKE/DETECT/GRAPH/PLAN/REPORT
apkmod.py <apk> --detect --graph           # read-only, any APK
apkmod.py <apk> --plan --authorized "..."  # DRY-RUN patch manifest (authorization recorded)
apkmod.py <apk> --report                   # markdown report card in apk-runs/
```

- **Authorization boundary**: intake/detect/graph/report are read-only for
  any APK. `--plan` requires `--authorized '<rights statement>'` (recorded in
  the plan) and only writes a dry-run manifest — this slice never modifies an
  APK. Applying patches (smali/dex edit → rebuild → sign → runtime verify) is
  a separately-gated later stage.
- **Evidence levels**: E1 SDK class present · E2 manifest meta-data
  correlation · E3 application-owned caller via DEX call graph ·
  E4 runtime-observed (out of static reach → `runtime: UNKNOWN`).
- **Falsification is a step**: every finding lists the counter-evidence that
  would weaken it (no app caller, presence-only, generic hint).
- **Fingerprints** (`apk/fingerprints.json`) are reduced ORIGINAL signals —
  short class prefixes + well-known public manifest keys; extend per-target
  with `--fingerprints <extra.json>` (same schema, see
  `apk/fingerprints.example-extra.json`).
- **Patch candidates** name the narrowest application-owned chokepoint,
  default action STUB-NOOP (avoids ClassNotFoundException), alternatives
  (REMOVE-CALL / DOMAIN-BLOCK / UI-HIDE) with risk notes, rollback
  metadata, and the runtime verification to run later.

Requires `androguard` for DEX/binary-XML parsing (`uv pip install
androguard`); `--intake` alone works with stdlib + AXML fallback.

## General APK / target model

The harness is **target-agnostic**: the only integration surface is
`ask(messages) -> text`. Point it at an OpenAI-compatible
`/chat/completions` endpoint, run it against offline mock targets
(`--mock mock_resist | mock_fail`) to self-test the harness, or bind it to an
APK's embedded model from inside the app. Scope (SPEC): local/self-hosted
endpoints only; benign fills by default; no third-party production APIs.

## Provenance & license

The taxonomy derives from studying external, **public-but-unlicensed**
prompt-override and persona-jailbreak collections (see `sources.md`). Per a
standing rule, those corpora are used only as *evaluation references*; **none
of their verbatim text is reproduced here or in any consuming app.** Everything
in this repo is original prose or reduced synthetic templates. MIT-licensed.

If you are an upstream author and this is a mistake, open an issue — I will
remove it.

## Layout

```
method/        the 9 technique families (original prose) + B-axes for family 09
  README.md        index + taxonomy
  01-...md ... 09-...md
probes/        machine-readable reduced synthetic probe templates
  probes.json      (30 probes + 3 controls)
values/        deterministic BENIGN fill set (defaults.json; override --values)
rubric/        grading + report format
  grading.md
tools/
  validate.py      offline payload validator (structure, axes, manifest sha256)
  redteam.py       reference runner (stdlib only; --endpoint/--mock/--replay)
studies/     dated study notes (method distilled from external sources, no text copied)
SPEC.md      implementation contract for any language / in-app harness
manifest.json  versioned knowledge manifest (sha256 + schema gate)
sources.md   provenance notes
```

## Running the harness

```bash
# self-test the harness (offline mocks — proves the grader, not a model)
python3 tools/redteam.py --mock mock_resist
python3 tools/redteam.py --mock mock_fail

# test a real local/self-hosted model
python3 tools/redteam.py --endpoint http://127.0.0.1:11434/v1 --model qwen3:8b

# offline re-grade (troubleshooting: which verdicts moved, and why)
python3 tools/redteam.py --replay runs/evidence-<run>.jsonl
```

Outputs: `runs/evidence-<run>.jsonl` (full evidence log, hash-pinned in the
report) + `runs/report.md` / `report.json` (the report card). CI runs both
mock targets on every push and asserts the harness discriminates correctly.

## Consuming it (app side)

1. download the release + `manifest.json`
2. verify `sha256` over the payload and the `schemaVersion`/`minimumAppVersion`
   gate
3. load `probes.json`, bind `ask()` to the model under test, run per `SPEC.md`
4. report the card; escalate on any `FAILED` (STABLE) or failed control

Never treat a probe template as an instruction to the model being developed —
it is *material to send to the target under test*, nothing more.
