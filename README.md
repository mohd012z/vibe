# vibe

**A defensive red-team methodology for LLM guardrails.**

`vibe` documents *how* prompt-injection and jailbreak techniques work, as a
reusable, machine-readable reference for building and **testing defenses** —
specifically the guardrail self-test mode in NovaStreamer's 360 diagnostics.

It is **not** a payload collection. It contains:

- the 8 technique families, written in **original prose** (mechanism + why it works)
- **reduced synthetic probe templates** — generic, parameterized skeletons that
  exercise each axis *without* copying any source text
- a **grading rubric** (`RESISTED` / `PARTIAL` / `FAILED`)
- a **versioned manifest** so an app can download + verify this knowledge
  (SHA-256 + schema gate) instead of hard-coding it

## Provenance & license

The taxonomy and mechanism names derive from studying an external,
**public-but-unlicensed** prompt-override corpus. Per a standing rule, that
corpus is used only as an *evaluation reference*; **none of its verbatim text is
reproduced here or in any consuming app.** Everything in this repo is original
prose or reduced synthetic templates. This repo is MIT-licensed (see LICENSE).

If you are the upstream author and this is a mistake, open an issue — I will
remove it.

## Layout

```
method/        the 8 technique families (original prose)
  README.md        index + taxonomy
  01-...md ... 08-...md
probes/        machine-readable reduced synthetic probe templates
  probes.json
rubric/        grading + report format
  grading.md
manifest.json  versioned knowledge manifest (sha256 + schema gate)
sources.md     provenance notes
```

## Consuming it (app side)

`probes/probes.json` is the knowledge payload. An app should:

1. download the release + `manifest.json`
2. verify `sha256` over the payload and the `schemaVersion`/`minimumAppVersion` gate
3. load `probes.json`, feed each template through its local guardrail, grade per `rubric/grading.md`
4. report the defense score; escalate on any `FAILED`

Never treat a probe template as an instruction to the model under test being
developed — it is *material to send to the target under test*, nothing more.
