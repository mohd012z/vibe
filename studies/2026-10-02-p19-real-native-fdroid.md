# P19 real production native — F-Droid .so e2e + PLT-trampoline false positive (v0.25)

Date: 2026-10-02 · Branch: feat/p19-plt-false-positive (PR #26) · Author: Aliph
(Fatah-approved "proceed" sweep; native path on real production code)

## Gap this closes

P18/P19 native-provider verification ran on **synthetic-but-real** builds
(genuine cross-compiler output, small fixtures, no PLT entries modeled as
functions). The DEX path just closed its "no real production sample" gap
(v0.24, F-Droid APK). This round closes the same gap for **native**: the
production `analyze_native` + P19 idiom classifier, run on the real `.so`
files extracted from the F-Droid client APK.

## The sample (real, non-synthetic)

F-Droid client (`F-Droid.apk`, SHA-256 83d3fe52…, 12,537,183 B) carries
**four** native libs, one per ABI, all `libandroidx.graphics.path.so`
(AndroidX path native impl — the only JNI in the app):

```
arm64-v8a  10,096 B   armeabi-v7a  7,252 B
x86_64     10,760 B   x86          9,284 B
```

All four: exported `JNI_OnLoad`, imports
`{__cxa_finalize, __cxa_atexit, __stack_chk_fail, __system_property_get,
atoi, malloc, free}` (+ `__stack_chk_guard` on ARM32).

## Finding — P19 `string-ref-pair` false-fired on every PLT trampoline

Running the production classifier on the real arm64 lib reported
`string-ref-pair` on **10 of 16** functions — 7 `sym.imp.*` PLT stubs +
`entry0`. Root cause (structural, verified against the bytes):

The glibc-style aarch64 PLT entry is:

```
adrp  x16, 0x5000
ldr   x17, [x16, 0xf98]     # load the GOT slot
add   x16, x16, 0xf98       # recompute the SAME slot address
br    x17
```

That `adrp; add X16,X16,#off` is **byte-identical in shape** to the
genuine position-independent data reference the idiom hunts for — so every
import trampoline in every real aarch64 ELF false-matched. The synthetic
P19 fixture never had PLT entries as scanned functions, so the
"string-ref fires on EXACTLY ONE function" check passed — same gap class as
the v0.24 DEX bug: the counter-example only appears in production-shaped
input.

Two facts forced the structural (not heuristic) fix:

- r2 6.2.2's own `aflj` reports these stubs with `plt=None` — r2 does NOT
  mark glibc-style PLT entries, so filtering on r2's plt flag or on
  `sym.imp.`/`sym.plt.` names would be r2-version- and naming-convention-
  fragile.
- `entry0`'s pair (`adrp x0,0x5000; add x0,x0,0xc40`) is a **genuine**
  reference: 0x5c40 is `.fini_array` (the destructor pointer handed to
  `__cxa_finalize`) — it must keep matching. A name-based "skip entry0"
  rule would have been wrong for the opposite reason.

## The fix (structural, in the idiom matcher)

`_adrp_add_pairs` now rejects a candidate pair when the immediately
preceding instruction is `ldr Xj, [Xb, #off]` with `Xb == the adrp's
register` and `#off == the add's offset` — i.e. the `add` recomputes the
GOT slot that was just loaded (the trampoline). A genuine data ref never
has that slot load, so no real reference is dropped. Also corrected: the
returned ref kept r2's **original case** (previously lowercased — a
lowercased `str.android_graphics_path` would have been a mangled symbol in
the evidence).

## Verification (real data, production code path)

Differential on the real arm64 lib — pairs WITHOUT the guard vs WITH:

```
sym.imp.__cxa_finalize          1 -> 0   (GOT slot 0xf98, correctly dropped)
sym.imp.__cxa_atexit            1 -> 0   (0xfa0)
sym.imp.__stack_chk_fail        1 -> 0   (0xfa8)
sym.imp.__system_property_get   1 -> 0   (0xfb0)
sym.imp.atoi                    1 -> 0   (0xfb8)
sym.imp.malloc                  1 -> 0   (0xfc0)
sym.imp.free                    1 -> 0   (0xfc8)
entry0                          1 -> 1   (0xc40 = .fini_array — KEPT, genuine)
sym.JNI_OnLoad                  9 -> 9   (ALL genuine refs KEPT)
jni.createInternalPathIterator  1 -> 1   (KEPT)
```

**Only the 7 PLT trampolines changed; zero genuine references lost.**
Post-fix idiom output on the real lib: `string-ref-pair` on exactly
`{entry0, sym.JNI_OnLoad, createInternalPathIterator}` — the true data
references, nothing else.

Other real-native facts verified this round:

- r2 6.2.2 disassembles the real ARM32 lib correctly (capstone cross-check
  byte-for-byte on the 0x800 PLT), BUT `iI` reports **`bits: 16`** for the
  32-bit ARM ELF (e_ident[4]=1, machine=0x28 confirmed by raw header
  parse). The analysis is right; r2's metadata line is wrong. Recorded as
  an r2 quirk — `analyze_native` does not surface `bits`, so no vibebot
  code depends on it. (UNKNOWN: which rabin heuristic emits 16 — not
  chased; not blocking.)
- Real JNI_OnLoad = 112 insns, `mov w2, 6` (ABI 1.6), standard prologue —
  consistent with a small AndroidX JNI shim.

## Regression guard (committed)

7 pure unit checks (no new large fixture — the shapes are 4-instruction
constants, and the 12KB real libs stay in scratch, not the repo):

- PLT trampoline (x16/x15 base, hex and r2-6 '0' rendering, negative
  offset) → NOT a string-ref (4 checks);
- entry0/fini_array shape and symbol-rendered ref → STILL fires (2
  checks);
- unrelated earlier `ldr` (register offset / no offset) → does NOT
  suppress a following genuine pair (1 check).

## Honest limits (after this round)

- Native e2e now proven on real production `.so` for arm64 (idioms +
  functions + exports/imports), arm32/x86/x86-64 (functions + exports +
  imports + disasm correctness). The F-Droid app has no app-specific JNI
  beyond AndroidX's path impl, so "deep app logic" native e2e remains
  unexercised on this particular app (its native surface is genuinely
  small — that's a property of the app, not a gap in the tools).
- The PLT guard is shape-based for the **glibc** trampoline; musl/Bionic
  aarch64 PLTs use a different entry shape (typically `adrp; ldr; br`
  with the GOT slot in the loaded register — no `add`) and never matched
  the idiom, so no guard is needed for them (verified reasoning, not a
  run).
- r2 `bits:16` quirk on ARM32 ELFs: observation only; not fixed (r2 is
  subprocess-isolated, per license discipline).

## Methodology note (why this is trustworthy)

- Bug found by **running production code on production-shaped input** —
  the exact discipline that found the v0.24 DEX bug.
- Fix proven by a **differential** (no-guard vs with-guard) on the real
  lib: the change set is *exactly* the 7 PLT trampolines, nothing else.
- `entry0` (genuine, looks similar) preserved — the guard's precision was
  checked against a same-lib near-miss, not only on the PLTs.
- ARM32 disasm correctness cross-checked with an independent engine
  (capstone), since r2's own `iI` was known to be unreliable on that
  file's metadata.
