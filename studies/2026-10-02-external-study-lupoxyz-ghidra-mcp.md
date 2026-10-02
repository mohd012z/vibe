# Study — external sources → Vibe improvements (2026-10-02)

Anam pointed me at three external sources. One was fully readable
(`t.me/lupoxyz`, a public channel); two are member-restricted groups
(`@schdenfreude`, `@Modder_Guys` — Telegram only exposes their headers to
non-members, verified against raw HTML; content pending forwarded posts).
Plus a deep clone-study of `bethington/ghidra-mcp` v7.0.0 (Apache-2.0,
4.1k stars, 253 MCP tools, Java extension + Python bridge, 437 unit tests).

This note captures what each teaches us and the concrete items portable to
VibeBot / the vibe repo.

---

## A. t.me/lupoxyz ("🐺 Maloos") — public channel, fully pulled (posts #1186–1249)

A solo modder's work-log channel (July–Sept 2026): APK modding in action —
smali patches, native ARM/ARM64 patches, resource rebuilds, tool links.
Unlicensed third-party content: mechanisms recorded below, no verbatim
reuse of their scripts.

### Reading techniques (how they find the right spot)

1. **Kotlin Metadata name recovery** (highest value). In R8-obfuscated APKs
   method names collapse to single letters (`o()Z`), but the `@kotlin.Metadata`
   annotation on the class still carries the ORIGINAL signature list.
   Their example: metadata array entries `"f"→"Lwm0/a;()"`, `"container"`,
   `"o"→"()Z"`, `"isPremium"` → the positionally-aligned pair tells them
   `o()Z` IS `isPremium()Z`. No decompiler guesswork needed — the mapping is
   in the artifact. **This is a deterministic, androguard-tractable signal:
   androguard can read the class annotation bytes; pairing metadata entry
   order against the class's method list recovers original names for
   obfuscated Kotlin classes.**
2. **Obfuscated-enum spotting.** Pattern: a class with N static
   `sget-object` instances into itself + a `values()`-like method doing
   `filled-new-array {v0..vN}, [Lpkg/cls;` → that's a R8-shrunken Java enum
   (their example: a 4-state purchase enum "free/purchased/refunded/not
   purchased"). Detecting this shape in smali tells you where the
   license-state machine lives before reading a single method body.
3. **"Gated" vs "absent" (NOT OBSERVED ≠ IMPOSSIBLE, in the wild).** Their
   Bugjaeger free-vs-premium case: the free APK is *trimmed* — the premium
   code path is literally missing ("You have to write the missing code"),
   not just feature-flagged. The channel explicitly distinguishes this from
   the flag-flip case. Exactly the /360 principle, practiced.
4. **Hybrid-app awareness.** For a UniApp app the logic is NOT in DEX — it's
   in `/assets/apps/_UNI_<hash>/www/app-service.js`; they patch the JS
   (`setUserInfo` returning a `vip:{code:"PERMANENT"}` object). A Vibe
   `/apk` overview that reports "web assets present → logic layer may be JS,
   not DEX" would have saved them (and would prevent wasted DEX spelunking).
5. **r2 disassembly reading.** Their `pdf` boolean-getter case: init-flag
   pattern (`ldrb w8,[base,off]; tbnz/cbnz → lazy-init` twice), then the
   actual getter tail `ldrb w8,[x19,0x70]; cmp w8,0; cset w0,ne; b <epilogue>`.
   The patch decision: flip the `cmp w8,0` (so `cset ne` returns the inverse)
   or replace the tail with `mov w0,1; <epilogue>`. Teaching point: **the
   last compare-before-return in a `()Z` getter is the single best patch
   point** — and the epilogue (`ldp`/`ldr x30,[sp],#n; ret`) must be
   preserved, which is why the early-return patch copies it.
6. **ARM patch-encoding facts** (standard ISA encodings, verifiable against
   the ARM Architecture Reference — architecture facts, not their content):
   ARMv7 `mov r0,#1` = `01 00 A0 E3` (BE bytes), `mov r0,#0` = `00 00 A0 E3`;
   ARM64 NOP = `1F 20 03 D5`; ARMv7 NOP = `00 F0 20 E3`. Their bigger table
   (floats/doubles/booleans) is all MOV-with-immediate-rotation + VMOV —
   i.e., a *derived* table. A patch-planner can compute these, not ship them.

### Build/install techniques

7. **public.xml regeneration.** When you add/remove resources, apktool
   rebuild fails on resource-ID mismatch because `public.xml` pins the old
   IDs. Their fix: a small Node script scans `res/values/*.xml`, collects
   (type, name) pairs, sorts both, and re-emits `public.xml` with fresh
   `0x7f<typeHex><entryHex>` IDs. Mechanism: **the ID table is re-derivable
   from the resource sources** — deterministic, no magic. (Also: it sorts
   types and names — stable output.)
8. **Split-APK install.** `adb disconnect` (all) → `adb connect <ip>:<port>`
   (wireless debug port) → `adb install-multiple base.apk split_config*.apk`.
   `install-multiple` handles base-then-splits ordering; a plain `adb
   install` of the base alone fails on split apps.
9. **Flag-flip ad removal.** Their MobileAds case: patch `const/4 v2, 0x1`
   → `0x0` at the `AtomicBoolean` construction site for
   `mobileAdsInitStarted`. General pattern: **find the boolean FIELD that
   gates the subsystem, then patch the const at its init site** — one
   instruction, no method rewriting. (The inverse of #5's getter tail: field
   init vs read site — pick whichever has the single clean const.)
10. **Billing checkpoint.** The money check is where `purchase.purchaseState
    == Purchase.PURCHASED` is consumed (Kotlin: inside `setPurchaseStatus`'s
    `forEach`; the `$lambda$0` naming tells you it's the first lambda).
    Locating the enum-compare on the billing state, not the billing *client*,
    is the shortcut.

**License note:** lupoxyz is an unlicensed third-party channel. The items
above are mechanism-level facts (several are plain ISA/Android-platform
behavior). We do not copy their scripts or tables into vibe.

---

## B. bethington/ghidra-mcp v7.0.0 — clone-study (dev branch)

Architecture: Java Ghidra extension (GUI plugin 239 endpoints + headless
server 226) exposing HTTP on 127.0.0.1:8089; Python MCP bridge
(`python/bridge_mcp_ghidra/`, 15 modules, ~4.5k lines) translating to MCP
tools for AI clients; 57 Python test files; Gradle local / Maven CI dual
backend.

### The five portable ideas (ranked by Vibe impact)

1. **Mechanical falsification of AI claims (`falsify.py` + DOC_REFUTED).**
   After the AI documents a function, deterministic checks compare the
   claims against disassembly FACTS: declared calling convention vs the
   callee's actual `RET n`; plate-documented params vs the live signature;
   a `Get*` name on a function that writes globals; plate/prototype return
   contradictions. A tier-1 contradiction marks the function
   `DOC_REFUTED`, seeds an audit with the finding, and re-queues it. Their
   rule: "the disassembly is the authority; never assert what it
   contradicts." → **This IS the /360 Validator+Falsifier stage, and it
   shows it can be ~100% deterministic — no AI in the loop to refute.**
   Vibe equivalent to build: for each CLAIM in our claim machine, generate
   the mechanical check (e.g. a "method X is called from Y" claim is
   falsified by re-scanning DEX for the invoke; a "native export exists"
   claim by re-reading the .so dynsym). Cheap, androguard-only where
   possible.
2. **Cross-version function hashing (`computeStrictHash`).** Normalized
   opcode sequence → SHA-256: in-body jumps → `REL:<offset>` (relative to
   function entry), calls to known functions → `CALL_EXT`, external data
   refs → `DATA_EXT`, small immediates (|imm| < 0x10000) kept, large ones →
   `IMM_LARGE`, registers → `REG:<name>`. Same hash = same logic across
   builds even with different base addresses; then documentation
   (names, types, comments) PROPAGATES from the best-documented version to
   all matching versions, with globals matched by (instruction offset,
   operand index) rather than address. → **Vibe's "memory candidate
   promotion" across app versions**: our EntityResolver's fingerprints could
   adopt this normalization for methods (DEX bytecode normalized the same
   way: const/string literals bucketed, invoke-targets by resolved
   entity), so validated findings on v1 of an app carry to v2 as STRONG
   candidates instead of UNRESOLVED. This is the missing piece for
   /360's "learns only from validated outcomes" — the outcomes currently
   die with the APK.
3. **Completeness scorer with forgiveness.** 0–100 documentation-hygiene
   score: per-item deduction breakdown, but the *effective* score forgives
   unfixable deductions (decompiler phantoms, API-mandated `void*`,
   compiler artifacts), log-scaling prevents one bad category from burying
   the rest. Their own caveat — "the score measures hygiene, not truth" —
   is why falsification is a SEPARATE layer. → Vibe already rejects
   percentages (coverage statements instead); the transferable part is the
   **two-axis structure**: an *actionability* axis (what can this session
   still fix) strictly separate from a *truth* axis (claims vs
   disassembly). Our 18-stage `/investigate` summary should split "gaps we
   can still close with available providers" from "gaps closed only by
   unobservable claims" — same idea, our vocabulary.
4. **Lazy capability loading + discovery tools.** 253 tools would break
   some LLM providers outright (Gemini rejects the whole request: schema
   compiles to too many constrained-decoding states). Their fix: register
   only default groups (`listing,function,program`) on connect; expose
   `search_tools("rename function")` (searches the FULL catalog, returns
   the exact `load_tool_group` call needed), `list_tool_groups`,
   `load_tool_group`, `check_tools`. → **VibeBot's command surface is
   growing (14 commands now); when it crosses ~20, split L0 (always
   advertised) from a searchable registry** — `/plan` already does
   capability discovery for analysis methods; the same shape applies to
   bot commands. Also validates our "cheapest method first" rule: their
   minimum-viable read-only set is exactly 4 closed tools
   (`get_metadata`, `list_methods`, `get_entry_points`,
   `decompile_function`) — entry points + listing supply addresses,
   decompiled bodies name callees, which feed back in. That's our
   `/apk`→`/map`→`/xref` loop.
5. **Strict target routing.** `GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS=1`:
   every program-scoped call must name its target, else a loud error —
   because a call that omits the selector silently operates on whichever
   program is "current" (a hazard with multi-program/multi-client).
   → **Confirms VibeBot's `--sha`-required stateful commands are the right
   call**, and suggests we document the invariant explicitly: no command
   may fall back to "most recent session." (We already refuse; make it a
   tested invariant.)

### Also worth adopting (mechanics)

- **Batch = atomic.** Their write operations are all-or-nothing batches
  (93% fewer round-trips). P21 ChangeSet must batch + atomically apply —
  a half-applied patch set is worse than none.
- **Convention enforcement lives in the tool layer** (auto-fix / warn /
  reject tiers), not in prompts — "the tool knows the rules; the model just
  makes the call." Vibe: validation gates belong in providers/claim
  machine, never in the AI's system prompt.
- **Oracle pattern for runtime claims.** Differential oracle (call
  reimplementation AND original over an input vector, diff) vs call-only
  oracle (call original with chosen inputs to confirm/refute a
  documentation claim). "Calling is the dangerous half: a totally-wrong
  address faults and is contained; a SLIGHTLY-wrong one runs real code
  mid-function and corrupts live state that no restart undoes." Hence
  call is OFF by default (`GHIDRA_MCP_ORACLE_CALL=1`) and refuses absolute
  addresses by default. → This is the exact gating P17 (Frida runtime
  layer) needs: E5 evidence via call-only verification, off by default,
  named-exports only, no raw addresses.
- **File-root containment.** `GHIDRA_MCP_FILE_ROOT`: any filesystem-path
  endpoint canonicalizes its input and requires it under the root
  (path-traversal guard). → Our `/apk <path>` acceptance should
  canonicalize + confine to the work dir; trivial to add, prevents a bot
  reading arbitrary host paths.
- **Security posture.** Loopback-only default; non-loopback bind REFUSES
  to start without a token; script-exec endpoints off by default. → Our
  gateway is already token+allowlist gated; the "refuse to start on bad
  bind" pattern is the one we should copy (fail closed, not warn).
- **Test pitfalls (from their changelog, real bugs they caught):**
  (a) a package split silently DEFANGED a unit test — mocks patched the
  re-export namespace (`bridge.os`) while calls happened in the new module
  (`static_tools.os`); the test passed whether or not the code worked.
  *Mock patch targets must be the module where the call happens.*
  (b) version-fallback drift shipped green because only `pyproject` vs `pom`
  were compared, not the `__init__.py` fallback — they added
  `test_bridge_fallback_version_matches_pom`. *Every copy of a version
  string gets a consistency test.*
  (c) release-notes pipeline "invented a number" via a softened
  `2>/dev/null || echo unknown` fallback — fixed by reading the same source
  the build uses, with no fallback. *CI must never soften a missing value
  into a plausible one.*

---

## C. Restricted sources (content pending)

- `@schdenfreude` (1,360 members, "Schadenfreude Reversing Group", channel
  `@schdnfrd`) and `@Modder_Guys` (5,192 members) + its
  `@Coding_Guys`/`@CompileHub`/`@Modder_Hub` family: member-restricted;
  public preview exposes header + rules only (verified via raw HTML — zero
  message widgets). Awaiting forwarded posts / exported chat history from
  Anam. Modder_Guys metadata says it's an APK-modding Q&A community (rules
  forbid asking to remove their "Modder" watermark) — expect apktool/smali
  Q&A threads once readable.

---

## D. Concrete Vibe backlog from this study (ordered)

1. **Falsifier layer (deterministic)** — mechanical claim checks in
   `claims.py`/`/investigate` stage 17; androguard-only checks first
   (re-scan invoke; re-read dynsym). Highest /360-alignment, zero new deps.
2. **Kotlin-metadata name recovery** — `dexutil` reads `@kotlin.Metadata`,
   positionally pairs d2 entries with class methods; emits as
   PROBABLE-name candidates (metadata-derived = strong, but obfuscator can
   have stripped/altered it → never EXACT). Directly usable `/find` fuel.
3. **Cross-version method fingerprinting** — adopt normalized-sequence hash
   (B2) as a NEW fingerprint kind in EntityResolver, so validated findings
   carry across app versions as STRONG, not UNRESOLVED.
4. **Obfuscated-enum detector** — smali pattern (static self-referential
   instances + filled-new-array values()) → label "license/state enum
   candidate" in `/map`.
5. **Hybrid-app layer detection** — `/apk` overview reports bundled web
   assets (`/assets/**/app-service.js` etc.) → "logic may be JS, not DEX"
   coverage note.
6. ~~**File-root containment** on all path-accepting commands (D-5 from B)~~
   — DONE (v0.17): `Gateway(file_root=…)` / `VIBE_FILE_ROOT` env (opt-in,
   GHIDRA_MCP_FILE_ROOT pattern); all 13 path-accepting handlers route
   through `_artifact()`; unset → unchanged (no-gate), set → outside-root
   + `../`-escape refused (NOT OBSERVED outside the root).
7. ~~**`/investigate` summary split**: actionable-gaps vs unobservable-gaps
   (B3 structure, our vocabulary)~~ — DONE (v0.17): `deepdive.classify_gaps`
   (pure) — native-provider stages (11/12) = **actionable** (install r2/ghidra
   + re-run); runtime/data-boundary stages = **unobservable** (NOT OBSERVED
   != IMPOSSIBLE); rendered under the /investigate card.
8. ~~**L0/L1 command split + searchable registry** when surface > ~20
   commands (B4)~~ — DONE (v0.17): `registry.py` (single source of truth,
   tiered) + `/commands [query]` searchable surface. /help kept short and
   intact; L1 found by keyword.
9. **P17 oracle gating spec**: off-by-default, named-exports only,
   call-only vs differential (B, oracle) — design note before any Frida
   work. (STILL OPEN — needs a Frida runtime on the host; not buildable
   androguard-only. The build "P17" label is reused for the Kotlin
   @Metadata name recovery, item #2 — that one is DONE; this Frida oracle
   spec is its own backlog line.)
10. ~~**Invariant tests**: no "most recent session" fallback (B5); version
    string consistency across `__init__`/pyproject (B, test pitfalls)~~
    — DONE (v0.17): test asserts `/find`/`/xref` without `--sha` are refused
    (no silent last-session use) and `__init__.__version__` is X.Y.Z and
    matches the build (bumped to 0.17.0 — it had been stuck at 0.1.0).

Items 1–6 are androguard-only → buildable on this host today, same workflow
(branch + TDD + PR, Fatah merges). 2, 3, 4, 5, 6 are small; 1 is the
meaty one (claim-check registry + /why integration).
