# Study — ARM64 corpus + Python projects (2026-10-02, batch 2)

Anam's second study batch. Provenance is uneven — recorded honestly per
source:

| Source | Access | What was actually studied |
|--------|--------|---------------------------|
| `bicky007/100-python-projects` | FULL (README + all project listings) | General "100 Days of Code" bootcamp: games, bots, Flask, scrapers, pandas. NOT an RE repo. |
| `exercism.org/tracks/arm64-assembly` | FULL via the track's **open-source repo** (`exercism/arm64-assembly` cloned, 79 practice exercises, each with reference `example.s` + C unity test harness + Makefile) | The ARM64 corpus that actually exists on the track. |
| `metanit.com/en/assembler/arm64/` | **BLOCKED** — JS bot wall (2,919-byte challenge on every URL, real browser too); Wayback CDX "Temporarily Offline"; archive.today 404s on all domain rotations. Recovery ladder (web/blocked-page-recovery skill) exhausted. | NOT studied — no content, no guessing. Retriable when Wayback is back up or from an archive. |

---

## A. The ARM64 corpus (from exercism reference solutions)

### A.1 The ABI contract (the Makefile is the spec)
- **AArch64 System V**: first integer arg in `x0`, **return value in `x0`**,
  args 2–8 in x1–x7; caller-saved x0–x18, `x29`=FP, `x30`=LR, `sp`=SP.
- Cross-compile: `aarch64-linux-gnu-as` / `-gcc`; run under
  `qemu-aarch64 -L /usr/aarch64-linux-gnu` when host ≠ aarch64.
- Flags: `-Wall -Wextra -pedantic -Werror -std=c99 -fPIE` +
  `-pie -Wl,--fatal-warnings` — **tests fail on warnings**.
- Every function is verified by a **C test harness** (unity) — this is the
  model for *any* native-code change: a function is only "fixed" when the
  harness passes, not when the disassembly looks plausible.

### A.2 The idiom corpus (each a recognizable instruction signature)
| Idiom | Signature (mnemonic sequence) | Seen in |
|-------|-------------------------------|---------|
| **Position-independent address load** | `adrp xN, label` + `add xN, xN, :lo12:label` | hello-world, every string reference |
| **Byte copy loop** | `ldrb wN,[xM],#1` / `strb wN,[xK],#1` / `cbnz wN, .loop` (post-increment + conditional-branch-back) | two-fer `APPEND` macro |
| **Null-coalesce** | `tst x1,x1` + `csel x2, x1, x2, ne` | two-fer (name ?: "you") |
| **popcount** | `clz` + `ror` + `eor` (clear highest set bit) loop, counter in x0 | eliuds-eggs — NO per-bit loop |
| **Even/odd test** | `tbz xN, #0, .even` (test-and-branch on bit 0) | collatz |
| **Fused multiply-add** | `madd xN, xA, xB, xC` (x = A*B+C, one instruction) | collatz `3n+1` |
| **Bitset membership** | `lsl` (build 1<<k) + `tst xN, xK` + `bne .reject` + `orr` (set bit) | isogram |
| **ASCII case fold** | `orr xN, xN, #32` + `sub #0x61` + `cmp #26` + `bhs` (unsigned range) | isogram |
| **Loop skeleton** | `cmp`/`beq .return` … `b .loop` (forward jump back) | all |
| **Return** | single `ret` (x30) | all |

These are **architecture facts / compiler-output patterns** (stable ISA
behavior), not someone's proprietary content — the exercism repo is
MIT/BSD-licensed anyway.

### A.3 What this means for Vibe (the transferable insight)
lupoxyz shipped a *memorized* ARM/ARM64 hex-patch table. This corpus shows
the better form: **recognize a function by its normalized instruction
sequence, not by hex bytes.** That is exactly the shape of a *native
function classifier* for the Radare provider — a pure function over
normalized mnemonics (registers bucketed, addresses normalized) that
flags: `popcount-loop`, `case-fold-scan`, `bitset-test`,
`adrp+lo12-pair` (→ string reference), `madd-3n+1`, `tbz-bit0` (parity),
`copy-loop`. Each flag is E3 evidence ("this function's logic matches the
popcount pattern") — the same /360 claim discipline, at the native layer.
It also upgrades `/investigate`'s native stages from "n/a" to pattern
names even before a human reads the disassembly.

**Native test-harness pattern** (A.1) → the P17/P21 spec: a modified or
re-implemented native function is VALIDATED by a C harness under qemu,
never by "the diff looks right." That is the E5-adjacent static proof
layer, and it maps 1:1 onto our evidence model.

## B. 100-python-projects — what's actually in it
A bootcamp completion repo (456 commits, Jan–May 2024). Categories: games
(Snake/Breakout/Pong via turtle/tkinter), automation bots (Selenium logins,
auto-follow, data entry), Flask REST APIs, scrapers (BeautifulSoup +
requests → CSV), pandas/NumPy/matplotlib analysis, Tkinter desktop apps.

**Honest assessment: low direct Vibe relevance** — it is general Python,
not RE, and much of it (games, social bots) we never want to emulate.
Three structural patterns worth borrowing:
1. **Scraping pipeline shape** — requests + BeautifulSoup + CSV sink +
   retry: the skeleton our (future) Play-Store-metadata intake for `/apkdl`
   should follow if it ever exists.
2. **Flask/REST API pattern** — routing + JSON + auth middleware: the
   shape of our own api_server if it grows beyond the bot.
3. **SQLite persistence** — used across several projects; note that our
   session store is already JSON-per-SHA, which is the more honest choice
   (reproducible per artifact) — no change needed, just recorded.
4. **One data-analysis project ("Android App Store Analysis")** is
   on-topic (ranking APK market data) — a possible reference for a future
   `/apk`-at-scale survey tool, not for now.

## C. Blocked: metanit ARM64
The classic ARM64 tutorial series (lesson-per-topic: registers, addressing
modes, arithmetic, branches, …). Unreachable today (bot wall + Wayback
down). It would mostly *teach the same corpus A.2 covers from the
instruction-set side*; nothing in this note depends on it. Retriable when
archive.org is back up.

## D. Backlog additions (appended to the 2026-10-02 external-study list)
11. ~~**Native function-pattern classifier** (pure, over normalized
    mnemonics; E3 flags) in `native.py` — testable with FakeRunner today,
    activates when r2 is installed. *Highest-value ARM64 item.*~~ —
    **DONE (P15, v0.14)**: `native.classify_function` recognizes 6 idioms
    (popcount-loop, case-fold, bitset-test, tbz-parity, fused-madd,
    string-ref-pair) by normalized sequence (not hex), E3, wired into
    `/native` + `render_native`, FakeRunner e2e. Real r2 + a real .so is the
    ground-truth to add.
12. ~~**qemu-aarch64 harness note** for P17/P21 validation spec (a native
    change is proven by C tests under qemu, not by diff appearance).~~ —
    **DONE (P16, v0.15)**: operationalized as `harness.py` (`/harness <dir>`)
    + spec `studies/2026-10-02-native-harness-validation-spec.md`.
    FakeRunner-e2e; real-host honest degrade (no qemu/cross-compiler here).
13. ~~xmatch.py (in-flight v0.11)~~ — **DONE → P12** (see §E).

## E. xmatch.py (v0.11) — RESOLVED
`tools/vibebot/xmatch.py` (cross-version fingerprinting) is complete and
committed (v0.11). The flagged bug is fixed and TDD surfaced three more,
each a real parser/matcher fix:
1. **`CALL:` dot separator** — `CALL:{cls}.{meth}` so it aligns with a
   Radare-resolved `Class.method` target cross-provider.
2. **Identity tiebreak** — self-match exposed 14 fixture methods → 8 unique
   fps (4 identical `<init>`s, 4 identical stubs), so bare SHA-256 made even
   a method match *itself* AMBIGUOUS. Fixed: a shared fp disambiguates by
   (class, name) — same logic AND identity → EXACT; same logic but no unique
   identity → AMBIGUOUS. Self-match is now 14/14 EXACT.
3. **Name tier keys on method NAME, not (class, name)** — across versions the
   class is usually renamed/refactored too, so name is the honest cross-
   version signal; the callset is the STRONG/PROBABLE tiebreak and a name
   shared by >1 src method is AMBIGUOUS (same discipline, one level down).
4. **Immediate base is notation, not identity** — `0x8000` and `32768` are
   the same constant; parse by the base as spelled, emit the value, bucket
   magnitudes ≥ 0x10000 as IMM_LARGE. Register operands (`v0`) must not be
   read as the immediate (const/4 prints `v0, 2`).
**Known limitation (documented, not a bug):** branch-target collapse to `L`
is UNVERIFIED against a branch-bearing DEX (the fixture has no branches).
Worst case it under-matches (a method differing only in loop size falls to
STRONG/PROBABLE by name) — it can never over-match, so it is safe by
construction. A real branchy APK is the ground-truth to add.
