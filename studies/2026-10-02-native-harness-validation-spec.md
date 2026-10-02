# Native-harness validation spec (backlog #12 → P16, v0.15)

**What this is.** The top of the /360 evidence chain: prove that a *native
(ARM64) change* actually **behaves** by running a C test harness under
qemu-aarch64 and observing the test result — never "the diff looks right".

The P15 pattern classifier (E3, static) tells you *where* to change. This
spec (E5, dynamic/runtime) proves the change *works*. Together they close
the loop: `P15 → patch → P16`.

## Why (the /360 rule it enforces)
- A static patch can be *syntactically* correct and still *behaviorally*
  wrong (wrong register, wrong branch, clobbered callee-saved reg, wrong
  endianness assumption). "The bytes look right" is **NOT OBSERVED**, not
  proof.
- E5 (runtime observation) is the only tier that can establish that a
  specific build *does* something. It is also the **ceiling**: a green
  harness proves *this build passes this test*, not that the change is
  correct in general. The test's coverage bounds the claim.
- **NOT OBSERVED ≠ IMPOSSIBLE.** No qemu / no cross-compiler on the host →
  the validation is NOT OBSERVED (capability gap), which is *not* the same
  as the change being wrong. The engine degrades to that honestly; it never
  fabricates a pass and never crashes.

## The build recipe (NOT hand-rolled — exercism arm64-assembly, verbatim)
Grounded in the public exercism `arm64-assembly` track `templates/Makefile`
(2026-10-02 external study). These are documented toolchain facts, not
reverse-engineered constants:

| step | command |
|------|---------|
| cross-compile C | `aarch64-linux-gnu-gcc <CFLAGS> -c -o out.o in.c` |
| assemble arm64  | `aarch64-linux-gnu-as -o out.o in.s` |
| link (pie)      | `aarch64-linux-gnu-gcc <CFLAGS> <LDFLAGS> -o tests <objs>` |
| run (x86 host)  | `qemu-aarch64 -L /usr/aarch64-linux-gnu ./tests` |
| run (a64 host)  | `./tests` (no qemu needed) |

```
CFLAGS  = -g -Wall -Wextra -pedantic -Werror -std=c99 -fPIE
LDFLAGS = -pie -Wl,--fatal-warnings
```
`-Werror -pedantic` + `--fatal-warnings` are deliberate: the harness must
fail loudly on *any* warning, so a "passes" is not a "compiles with a
warning we ignored".

## Verdicts (E5)
| verdict | meaning | evidence |
|---------|---------|----------|
| **SUCCESS** | ≥1 test observed, 0 failed | E5 runtime |
| **FAILURE** | ≥1 test failed | E5 runtime (falsifies the change on this build) |
| **NOT OBSERVED** | no toolchain / build failed / no parseable test | E0 (capability gap — no claim either way) |

## What shipped (v0.15, `harness.py`)
- **PURE core** (no process, no toolchain): `detect_toolchain` (injectable
  `which`), `build_cmd_c/asm/link`, `run_cmd`, `parse_harness`,
  `validate_native`. Testable with a `FakeRunner`.
- **runner seam**: `HarnessLike` / `RealSubprocess` — mirrors P5/P15's
  injection pattern. A failure at any stage is an honest result.
- **`HarnessEngine`** (job): artifact = a source **dir**; auto-discovers the
  `.c` / `.s` files (so `/harness <dir>` is self-contained); writes a report
  JSON so `/report` works; emits an E5 finding on SUCCESS/FAILURE, an E0
  "NOT OBSERVED" finding otherwise.
- **`/harness <srcdir>`** route + HELP + deploy COMMANDS (redeploy needed to
  show in the live Telegram menu).

## Honest limitation (disclosed, not a blocker)
This host has **no `qemu-aarch64` and no `aarch64-linux-gnu-*` cross
toolchain** (only native x86 gcc), so the *real* behavioral run is NOT
OBSERVED here — the engine's real-host e2e asserts exactly that (degrades to
NOT_OBSERVED, no E5 claim). The SUCCESS/FAILURE paths are fully exercised via
`FakeRunner` + a fabricated toolchain. **Ground truth to add:** install
`qemu-user + gcc-aarch64-linux-gnu` (the P0 toolchain doc) and run a real
arm64 C harness end-to-end.

## Backlog status
#12 **DONE** (operationalized — not just a note). #2 Kotlin `@Metadata`
remains ON HOLD.
