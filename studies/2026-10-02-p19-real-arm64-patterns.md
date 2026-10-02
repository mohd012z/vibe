# P19 — Real-ARM64 pattern e2e (v0.20)

**Status: DONE — folded into PR #6 (feat/native-r2-verified).**
Date: 2026-10-02. Author: VibeBot (Aliph), initiated by Anam's "contineu".
Builds on P18 (same PR): P18 installed real radare2 6.2.2; P19 adds the
missing real **aarch64** target so the P15 pattern classifier is finally
exercised against real ARM64 disasm (it had only ever run on FakeRunner).

## The gap
P15's native function-pattern classifier (popcount-loop, case-fold-scan,
bitset-test, tbz-bit0-parity, fused-madd, string-ref-pair) was designed from
the ARMv8-A ISA + the exercism reference corpus, but **every test used a
FakeRunner returning canned mnemonics**. No real ARM64 binary was ever
disassembled through the classifier. P18's x86-64 e2e left this explicitly
open (x86 mnemonics match no ARM64 idiom — honest, but unproven on ARM).

## Toolchain (user-space, no root)
- `binutils-aarch64-linux-gnu` 2.44 (the REAL `as`/`ld` — the `gcc-*`/`cpp-*`
  debs are metapackages). `dpkg -x` into scratch; the cross `as` needs
  `LD_LIBRARY_PATH=<extract>/usr/lib/x86_64-linux-gnu`.
- Built a shared object from committed aarch64 **assembly**
  (`tests/fixtures/arm64/pat.s`), one function per idiom:
  `aarch64-linux-gnu-as -o pat.o pat.s` + `aarch64-linux-gnu-ld -shared`.
- The `.s` is committed (not the `.so`) so the build is reproducible in CI
  with just binutils-aarch64. The data symbol for the string-ref target is
  `.hidden` (a global-symbol `adrp` fails to link `-shared` without -fPIC).

## Three classifier bugs found (real-ARM64 disasm exposed all three — the
canned fixtures were shaped to the *old* r2 rendering)
1. **Disasm bled across functions (false POSITIVES).** The command was
   `pdj {size} @0xVA` but r2 `pdj`'s count is **INSTRUCTIONS**, while `size`
   is **BYTES** (aarch64: 4 bytes/instr). So `pdj 8 @casefold` disassembled
   8 *instructions* = 32 bytes = casefold + the next 3 functions, and
   `casefold` reported `bitset-test / tbz-bit0-parity / fused-madd` that
   belonged to its neighbors. Violated the /360 evidence ceiling (claiming a
   function's logic from instructions that aren't its own). **Fix:**
   `aa; pdfj @0xVA` — function-BOUNDED (r2 stops at the function end), and
   the va-form seek (r2 names the first function `entry0`, so the symbol
   name is not stable).
2. **P2 case-fold missed.** r2 6 renders the immediate as `0x20` (hex, no
   `#`): `orr w0, w0, 0x20`. The classifier required literal `", #32"`.
   **Fix:** regex accepts `#32` OR `0x20`, and now requires the SELF-fold
   form `orr Xd, Xd, imm` (an `orr w1, w2, #32` into a different register is
   not the idiom).
3. **P6 string-ref missed.** r2 6 renders the idiom as `adrp x0, 0` +
   `add x0, x0, 0x278` (or a resolved symbol) — the pre-6 `:lo12:` label
   syntax is not what 6.x prints, so the `:lo12:` requirement matched zero
   real binaries. **Fix:** accept `adrp Xd, <any>` + `add Xd, Xd, <ref>` on
   the SAME register (register-match prevents any adrp+add in the window
   from false-matching); legacy `:lo12:` still accepted.

## Evidence (all on real r2 6.2.2 + real aarch64 .so)
- `pdfj @0xVA` is function-bounded: entry0 → 4 ops, casefold → 2 ops, etc.
- After fixes, each function reports EXACTLY its own idiom:
  `entry0`=popcount-loop, `sym.casefold`=case-fold-scan, `sym.bitset`
  =bitset-test, `sym.parity`=tbz-bit0-parity, `sym.affine`=fused-madd,
  `sym.stringref`=string-ref-pair. No cross-attribution.

## Test surface
- 6 pure drift checks (P2/P6 both renderings + same-register negatives).
- 5 real-ARM64 e2e checks (auto-skip w/ honest NOT OBSERVED when r2 +
  cross-binutils + fixture are absent): all 6 idioms present; case-fold and
  string-ref each fire on EXACTLY one function (the bleed regression);
  popcount fires exactly once.
- **Counts: 467 checks (r2+ARM64) / 457 (CI shape), was 457/451 at P18.
  Version 0.19.0 → 0.20.0.** apkmod + redteam green.

## Boundaries / unknowns (disclosed)
- aarch64 x86_64-host cross-asm only — no qemu run, so this proves the
  classifier on real ARM64 *disassembly*, not ARM64 *execution* (the P16
  qemu harness is a separate, still-unsupported path on this host).
- The committed `.s` is a synthetic idiom corpus (like the x86 `real.c`),
  not an extracted app library; a real Android `libxxx.so` would be the
  ultimate validation (needs an authorized target APK).
- Folded into PR #6 (same branch) — Fatah merges once for P18+P19.
