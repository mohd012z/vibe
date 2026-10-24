# Study — Smali reference books & cheat sheets (2026-10-24)

Anam sent "Smali Books and CheatSheets.zip" (5 PDFs). All are classic, freely
reusable references (public-domain / project wiki / academic), so facts are
reusable; the four rules we codified are restated in our own words in
`tools/vibebot/smali.py::PATCH_GUIDE` rather than quoted verbatim. Full
extraction + analysis is in OV `viking://resources/study/smali_books_study.md`.

## Provenance (recorded honestly per source)

| # | File | What it is | Access | Reusable? |
|---|------|-----------|--------|-----------|
| 1 | `Dalvik_opcodes.pdf` | Gabor Paller's Dalvik opcode table (hex→name+example) | full, public domain | yes — "public domain, please quote" |
| 2 | `Registers (smali wiki).pdf` | JesusFreke smali wiki — Registers page | full, project wiki | yes — grammar/facts |
| 3 | `TypesMethodsAndFields (smali wiki).pdf` | same wiki — Types/Methods/Fields page | full, project wiki | yes — grammar/facts |
| 4 | `Smali_An_Operational_Semantics….pdf` | Smali+ paper, Information 2020, 11, 130 (Laval) | full, MDPI (open access) | yes — the formal citation |
| 5 | `Smali_coding_guide_for_beginners.pdf` | havocgb, XDA, 2013 — SystemUI smali guide | full (2013, ICS-era) | mechanisms only |

Extraction: pypdf 6.21.2 (uv venv) → one .txt per PDF; no OCR needed (all
had text layers). The Paller doc extracted as "binary" to grep (wide chars) —
read with a lenient decoder.

## What each teaches (mechanism, not marketing)

1. **Paller opcodes** — registers are 32-bit and TYPE-ERASED (one reg holds any
   value); **long/double use PAIRED registers** (a double at V0 occupies V0+V1);
   booleans are stored 1/0 and boolean ops compile to integer ops; examples are
   big-endian. He flags which opcodes he'd seen "in the wild" vs only from the
   constant list (and why to look at real dex with a dedexer). Cross-check vs
   our 114-opcode table: sound; the rows it adds are reserved `unused_XX` slots
   + a few wide `aget`/`aput` variants — our reduction is deliberate (full 257
   lives in the DEX Mapper via androguard, which is the correct decode path).
2. **Registers (wiki)** — `.registers` = TOTAL, `.locals` = NON-parameter;
   total = locals + params. Params live in the LAST n regs; a non-static
   method's first param is the implicit `this`. **p0/p1 naming exists exactly
   so you can bump `.locals` without renumbering the params** (baksmali's
   default). J/D args take TWO slots; invoke lists must name both halves.
3. **Types/Methods/Fields (wiki)** — the exact emit grammar: primitives
   single-letter (V=return-only), objects `Lpkg/Name;`, arrays one `[` per dim
   (max 255), method refs `Lowner;->name(params)return` with ZERO separators,
   field refs `Lowner;->field:Type`.
4. **Smali+** — a full operational semantics for smali, notably the
   multi-threaded case (scheduling, communication, synchronization) prior work
   glossed over. This is the citation to back any formal/concurrency claim
   about smali behavior (e.g. "this patched method is called from N threads").
5. **XDA beginner's guide (2013)** — the workflow lore: `.dex ↔ .smali` never
   back to Java; one class = one `.smali` file; **write non-trivial logic in
   Java, baksmali a dummy APK, paste the method in** (don't hand-author
   loops/switch in smali); find literal encodings the same way (build→baksmali→
   read; 107.0f = `const/high16 0x435c`); find call sites via param types +
   logcat + cross-file search. Dated tooling (APK-Multi-Tool, Notepad++) but
   the mechanics survive.

## What we changed (this PR)

- `tools/vibebot/smali.py`: added `PATCH_GUIDE` (4 sections: register-safety,
  emit-grammar, insertion-workflow, literal-encoding) + `patch_guide(section)`.
  Stdlib-only, pure — no androguard, no I/O.
- `tools/vibebot/gateway.py`: `/smali guide [section]` surface + HELP line.
  `/smali` with no args now lists the guide option. Unknown section lists the
  valid ones (honest, no fake hit).
- `tools/vibebot/__init__.py`: `__version__` 0.26.0 → 0.27.0 (source change).
- `tools/vibebot_test.py`: +7 checks (all sections present, per-section
  selection, emit grammar, literal/IEEE-754, unknown-section honesty, module↔
  command drift ×2).

## Backlog (not in this slice — flagged for value × feasibility)

1. **r2ai Android patch-plan prompt** (separate app, gh-pages delivery): when a
   patch touches `.locals`/`.registers`, J/D args, or inserts logic, emit the
   register-safety + emit-grammar rules and recommend the Java→baksmali route
   for insertions beyond a const/return flip. (Landed in the r2ai skill doc;
   the in-app prompt change is a v3.7 build — see report.)
2. **apkmod.py `--plan`**: append a `patchGuide` pointer to the dry-run
   manifest so an authorized patch plan carries the register/grammar rules.
   Small, androguard-gated; deferred to keep this slice stdlib-clean.
3. **Full 257-opcode table**: keep the reduced table; the DEX Mapper already
   decodes real bytecode via androguard. Only revisit if an analyst asks for a
   `unused_XX`/wide-variant lookup.

## Not built (and why)

- No new smali assembler/disassembler — bit-level encode/decode stays P3 and
  goes through androguard (correct-by-construction), per the standing
  android-bytecode pitfall. This slice is reference + workflow, not codegen.
- No Smali+ formal verifier — that is a research direction, not a bot feature;
  the paper is kept as the citation anchor.
