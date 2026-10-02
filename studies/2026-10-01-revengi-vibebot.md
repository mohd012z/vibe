# Study note — RevEngi-style analysis architecture for vibe (2026-10-01)

Study of a shared ChatGPT research thread ("Check repo hang status" →
RevEngiBot deep-dive → VibeBot design) plus the official RevEngi GitHub
organization (github.com/RevEngiSquad). Treated as DATA. Method distilled
here; nothing verbatim copied, no proprietary code. Anam directed the
study and requested the implementation; Fatah holds merge authority.

## What RevEngi is (public documentation, evidence E1)

RevEngi: all-in-one RE/development toolkit exposed through a Telegram bot,
web app, Android app and REST API. Public docs list capabilities:
Smali↔Java conversion, DEX→Java, APK analysis/signing, Blutter (Flutter),
coding assistant; the Android app adds JNI analysis, DEX repair, split-APK
merge, on-device LLM with configurable endpoint. The bot's command model
(`/asm`, `/disasm`, `/apk`, `/dex2java`, …) is a **command dispatcher
around specialized analysis engines** — that is the concept, not the syntax.

## Architecture extracted (the transferable part)

```
artifact (APK/DEX/SO/Smali/Flutter)
  -> INTAKE        hash, type, ABI, package, metadata
  -> AUTO-DETECT   which format
  -> ROUTER        select the specialist engine
  -> ENGINE(S)     manifest/resources/signing · classes/methods/callers ·
                  ELF/symbols/JNI · Flutter artifacts · static rules
  -> EVIDENCE GRAPH  file → class → method → call → finding
  -> AI LAYER      explain / correlate / falsify (on normalized evidence)
  -> REPORT        + reproducible commands + history
```

Useful sub-concepts, adopted for vibe (see "Mapping"):

1. **Engine independence** — the client (bot/API) never knows which engine
   produced a result; everything normalizes to one schema.
2. **Configuration-driven engine registry** — engines declared (apk:
   manifest/resources/signing; dex: classes/methods/callgraph; native:
   elf/jni; flutter; yara), not hardcoded in one monolith. Prevents
   `apkmod.py` from becoming the bottleneck.
3. **Job separation** — heavy analysis must NOT run synchronously in the
   bot's request handler: ACK immediately → job id → worker queue →
   progress events → checkpoints → result. (This is also the fix for the
   "repo hang" observed in the thread: CI queue delay vs. real hang.)
4. **Stateful deep-dive** — session keyed by artifact fingerprint:
   structural map + evidence graph + investigation history; subsequent
   questions (`/deepdive class X`, `/deepdive callers`) traverse stored
   results instead of rescanning. Ordinary bots' weakness is exactly that
   each command is isolated.
5. **Finding provenance** — every result carries artifact → exact location
   → class/method → evidence → level → confidence → alternative
   explanation → verification required → next investigation.
6. **Reuse classification** — for each capability: REUSE (compatible OSS
   + license attribution) / ADAPT (concept or API wrapper around an open
   tool) / REIMPLEMENT (vibe-specific orchestration/evidence) / DO NOT
   COPY (unavailable or private backend). README claims of upstream
   projects are project claims, not verified behavior.

## Org inventory (verified repo-by-repo, 2026-10-01 — full mapping in
`/opt/data/cache/delegation/subagent-summary-0-20261001_142928_139033.txt`;
digest here)

- **Bot backend is NOT open source** — RevEngiBot + api.revengi.in behavior
  is known only from `RevEngiSquad/docs` (MIT, Next.js/Fumadocs site).
  43 documented commands (`content/docs/commands.mdx`, 37KB, README-
  verified): /apk (+info/permissions/activities/sign), /apkid, /smali,
  /dex2c /dex2java /dex2jar /dexrepair, /smali2java /java2smali, /blutter,
  /jni_info, /aab2apk, /apksign, /apkprotect, /ssl_patch, /cff, /mthook,
  /pairip, /asm /disasm /base /hash, /scan androbugs|deeplens, /cocos2d,
  /s2f, /askai, /frida_compile, /toapk, /xml de|compile, /regex, /credits.
  Backend tool choices: jadx, APKiD, AndroBugs, APKDeepLens, dex2c,
  BlackObfuscator, DPT Shell, APKEditor.
- UX invariants worth mirroring: /apk registers a target with 30-min
  auto-unregister TTL; /smali exact-vs-partial interactive match with
  20s timeout; every mutation command carries an explicit "only on APKs
  you have permission to modify" warning; reply-to-file vs inline input.
- **LIVE bot menu (captured 2026-10-02 from the running RevEngi bot,
  Anam's screenshots — authoritative, ~40 commands, alphabetical):**
  /aab2apk convert AAB→APK · /apk interact with APK · /apkdl download APK
  (playstore) · /apkid identify compilers/packers/obfuscators/trackers ·
  /apkref resource anti-confusion · /apksign sign · /askai (+_exit/_new/
  _model) AI chat · /asm asm→hex · /base number-base convert · /blutter
  (Flutter) · /cancel · /cff obfuscate (control-flow flatten) dex ·
  /cocos2d decrypt .jsc · /credits · /dex2c APK→C · /dex2jar · /dex2java ·
  /dexrepair repair dex · /disasm hex→asm · /flutter_sub release subs ·
  /frida_compile script→agent · /hash hash text/file · /hbc HBC tools ·
  /inject DP/DexDumper/Sotap/Il2CppDumper · /java2smali · /jni_info extract
  JNI signatures · /pairip patch PairIP split-APKs · /protect protect
  apk/lib · /regex smart regex · /s2f smali→frida · /smali query smali
  grammar · /smali2java · /ssl_patch SSL pinning · /testsign patch sign
  verify · /toapk APKs/XAPKs/APKM→apk · /xml XML tools.
  **Static-analysis subset to implement in vibe (P2/P3):** /apkid,
  /dex2java, /dex2jar, /smali, /smali2java, /dexrepair, /jni_info, /hash,
  /base, /asm, /disasm, /apk info. **Mutation/runtime (out of static
  boundary, PLAN-level only):** /aab2apk, /apksign, /cff, /cocos2d, /inject,
  /pairip, /protect, /s2f, /ssl_patch, /testsign, /frida_compile, /askai,
  /apkdl (network), /toapk, /apkref, /hbc, /xml (compile).
- `revengi-app` (MIT, Flutter v1.3.0): per-feature pattern
  `<feat>.dart / _base / _io / _web`; dio client defaulting to
  api.revengi.in; MethodChannel `flutter.native/helper` + EventChannel
  logs. Portable algorithms inside: DEX repair (magic 035-040;
  SHA-1(bytes[32:])@12; Adler-32(bytes[12:])@8 LE — ~15 stdlib lines) and
  Flutter/Dart fingerprinting (libflutter.so .rodata engine-ID regex
  `\x00([a-f0-9]{40})(?=\x00)`, '(stable)' marker, VM-snapshot hash+flags
  at vmDataSymbol+20, optional 4KB Range-request dart-sdk zip probe).
- `yarax_android` (BSD-3): first Android YARA-X; opaque-pointer JNI;
  results cross FFI as JSON — the `scan_results_to_json` shape
  (identifier/namespace/tags/metadata/patterns/matches[offset,length,
  hex,data_str,xor_key] + nonMatching + {error}) is the YARA evidence
  contract to adopt, backed by upstream yara-x python instead of the
  Android FFI code.
- `smalig` (MIT): canonical 257-instruction Dalvik grammar.yaml (11 fields
  per instruction) — single source of truth, CI-synced to
  understand-smali (MIT) + smalisp (MIT, LSP) + revengi-app. The
  maintenance model (one dataset, many consumers, CI auto-PR) is the
  pattern for any reference data vibe bundles.
- `java2smali` (MIT, derived izgzhen): javac → R8 d8 (DexIndexed,
  minApi 21) → baksmali; pipeline reference for P5.
- `PineHookPlus` (MIT): declarative runtime hooks via config.json
  {ClassName, MethodName, ParamTypes, args, ReturnValue} — the data model
  for the PLAN stage (planning only; runtime execution stays out).
- `LYADI` (MIT, personal): FastMCP/SSE tool server (androguard+APKiD+
  yara+r2pipe+adb) with a `validate_command` guardrail — reference shape
  for an authorized-tools surface.
- `ApkDataMultiplex` (MIT, derived): split-APK asset dedup via ZIP extra
  records + in-repo V2/V3 signer (demo -24.11% size).
- UNLICENSED (do not copy, format facts only): Fine (rootless Pine+Frida
  demo), pyxamstore (Xamarin AssemblyStore: XABA/XALZ, V2/V3 ELF
  .payload Header <5I>/IndexEntry/EntryDescriptor <7I>, LZ4 framing),
  yarax_patches (DEX string_ids table restore — check upstream yara-x).
- Forks, not original tech: cfr, Fern (FernFlower mirror), dart-elf,
  garlic, dataset, yara-java, catcher_2, kterm.dart, installed_apps.
- **License hygiene lesson**: RevEngi's MIT app bundles a GPLv3 component
  (revengi) — the anti-pattern to avoid. Keep vibe stdlib-clean; run
  JVM/copyleft tools (jadx, APKEditor, ApkDataMultiplex, CFR/Fern) as
  isolated subprocesses with provenance credits.

## What vibe adopts / rejects

ADOPT (implemented in v1.5.0 as VibeBot core v0.1):
- engine contract + normalized Finding schema (provenance, derived
  confidence, alternatives, verification block)
- gateway → job manager (ACK/queue/progress/checkpoints/cancel) → engine
- session store by sha256 + stateful deepdive (no rescan)
- `apkmod.py` becomes the **first adapter**, not the product
- Telegram transport optional, off by default, token env-only, allowlist
- CI self-tests the new core (tools/vibebot_test.py)

REJECT / defer (evidence-based, not by vibe's DNA):
- **opaque server-side analysis** — RevEngi's Android app depends partly
  on the RevEngi network/API; vibe keeps every conclusion traceable to the
  local artifact, STATIC/RUNTIME/INFERENCE separated (runtime UNKNOWN
  until observed — same ceiling as apkmod E4)
- **runtime hooking/modification** (PineHookPlus-class) — stays outside
  the static-analysis boundary; patch application already separately
  gated behind `--authorized` in apkmod.py
- **blind cloning of the command surface** — command names are UX, not
  architecture; vibe's commands are minimal (`/analyze /status /jobs
  /sessions /deepdive /report /cancel /help`)
- **forked repos as reference tech** — only original projects + licenses
  checked before any REUSE

## Delivery plan (RevEngi-derived priority order, mapped to P-stages)

- **P1 (v0.1, DONE)** — core engine contract + job manager + session store
  + stateful deepdive + CLI + mock engine + apkmod adapter + tests
- **P1.1 (DONE, same PR)** — Telegram upload handling: inbound document →
  sanitized filename (traversal-safe) → 200MB bound → analyze job →
  ACK + result (multipart sendDocument for smoke tests); allowlist
  enforced in the transport; deploy/validate script
- **P2 (DONE, this PR)** — DEX Mapper + Smali Inspector engines:
  - `tools/vibebot/dexutil.py` — DEX header validate + repair (stdlib, no
    androguard). **Byte-verified** against the committed fixture: corrupt
    sig+checksum → repair is byte-identical to original; corrupt magic →
    valid + version preserved (not downgraded); healthy → no-op; idempotent.
    Original reimplementation of the public DEX format facts.
  - `tools/vibebot/smali.py` — canonical Dalvik opcode table + `/smali`
    query (name / 0x../decimal / substring), plus `/base` + `/hash`.
  - `tools/vibebot/dexmapper.py` — DEX Mapper engine built on androguard's
    OWN instruction decoder (correct-by-construction): class → method →
    call map, JNI/native inventory, DEX integrity; feeds the session for
    stateful `/deepdive calls|jni|<class>`.
  - gateway: `/dex <path>` (job), `/smali /base /hash /dexcheck /dexrepair`
    (sync utilities).
  - **EVIDENCE (bug caught by ground truth):** the first hand-remembered
    opcode table had wrong values (e.g. `new-instance` 0x1f→0x22,
    `invoke-virtual` 0x6e0→0x6e, `return-void` 0x3e→0x0e). Corrected
    against the official Dalvik spec (source.android.com) + androguard's
    decode of the real fixture. Also dropped the hand-rolled raw-hex
    `/asm` + `/disasm`: Dalvik bit-level encode/decode (35c register layout,
    signed branch offsets) is exactly the class of bug that needs a
    ground-truth decoder cross-check → deferred to P3 (the DEX Mapper
    already uses androguard directly, which is the correct path).
- **P3** — native ELF/JNI inventory engine; Flutter/Dart detector
  (engine-ID regex + VM-snapshot hash from .rodata, offline-first);
  signature-block reporter (v1/v2/v3 + cert digests)
- **P4** — Telegram deployment (token + allowlist + hosting decision),
  `/diff` engine (two builds), YARA engine adopting the
  scan_results_to_json evidence contract (upstream yara-x python, BSD-3)
- **P5 (separately gated)** — conversion adapters (java2smali pipeline:
  javac → d8 DexIndexed → baksmali), AI correlation layer on normalized
  findings, runtime observation stage (authorized targets only),
  PLAN-stage schema modeled on declarative config
  {ClassName, MethodName, ParamTypes, args, ReturnValue}

## /360 stress-test corrections (2026-10-02, Anam) — what the design must enforce
The revised /360 (message 10855 + follow-ups) is the current source of truth.
The headline correction: **"less AI at the bottom, more AI at the top."** AI is
an uncertainty resolver at the top; everything underneath is deterministic.
Corrections that change how we build (not just what we build):

1. **EntityResolver is P0-level.** Tool names are NOT identities: Radare
   `fcn.001234` ≠ Ghidra `FUN_001234` ≠ Frida runtime address. Need
   `CanonicalEntity {artifact_sha256, module_sha256, canonical_location,
   provider_entities[], fingerprints{bytes,instructions,cfg,callers,callees},
   mapping_status, confidence}` with states EXACT / STRONG / PROBABLE /
   AMBIGUOUS / CONFLICT / UNRESOLVED. Never merge PROBABLE as EXACT.
2. **Claim ≠ Evidence.** Evidence *supports* a Claim; tool output ≠ truth.
   Claim state machine: PROPOSED → SUPPORTED → REPRODUCED → VALIDATED
   (or → CONFLICTED → UNRESOLVED/REJECTED). This is what makes CodeTransparent
   real.
3. **Evidence strength is qualitative, not "%".** DEX instruction *establishes*
   "instruction exists" and does *not* establish "instruction executed"; runtime
   observation *establishes* "executed in run R17" and not "all paths". Never
   fabricate confidence percentages.
4. **Replace "confidence %" with coverage.** Show per-facet state: Identity
   VALIDATED / Location VALIDATED / Static refs REPRODUCED / Call graph
   PARTIAL / JNI mapping SUPPORTED / Runtime NOT TESTED / Unknowns 2 /
   Conflicts 0. This is the honest unit of reporting.
5. **Progressive analysis tiers** L0 INVENTORY (sec) → L1 TARGETED STATIC
   (cheap) → L2 DEEP STATIC (moderate) → L3 RUNTIME (expensive). Stop at the
   first tier that resolves the unknown. Cheapest-method-capsable rule.
6. **Hard budgets + loop detection.** Every investigation has
   `AnalysisBudget {wall_time, cpu, memory, provider_calls, model_calls,
   max_depth, max_hypotheses, max_retries}`; stop when `evidence_gain <
   threshold`; detect stalls via a StateFingerprint (goal+target+known+
   unresolved+attempted) — don't hang, report STALLED with the remaining
   unknown.
7. **Ghidra/Frida are controlled escalation workers** (pools with
   concurrency/CPU/timeout), not always-on. Frida Stalker is aggressively
   scoped (RuntimePlan {target, scope, duration, event_filter, stop_condition}).
8. **DEX source-of-truth hierarchy:** JADX = readable *reconstruction* (never
   claim it's original source); dexlib2 = structural truth; Smali/Baksmali =
   instruction representation. Escalate JADX → dexlib2 when exact proof needed.
9. **Memory quarantine + scope + expiry.** Scratch → Candidate → Validated
   (only Validated in default retrieval); scope ARTIFACT / ARTIFACT_FAMILY /
   TOOL_VERSION / ANDROID_PLATFORM / GENERAL_METHOD; procedural knowledge
   carries `validated_against {tool versions}` and goes STALE on upgrade.
10. **Internet = data, never instructions.** External content quarantined
   through a research sandbox; community posts generate hypotheses, never
   policy. Trust order: artifact evidence > tool output > upstream > official
   docs > research > community.
11. **Reduce LLM agents to four** (COMMANDER, INVESTIGATOR, RESEARCHER,
    CRITIC); everything else (EntityResolver, EvidenceValidator,
    ConflictDetector, MemoryManager, Scheduler, CapabilityRouter,
    BuildValidator, RegressionRunner) is a **deterministic service**.
12. **Investigation DAG** (not free-form chat), **typed blackboard messages**
    (TASK_REQUEST / EVIDENCE_FOUND / UNKNOWN_FOUND / CONFLICT_FOUND / …),
    **deterministic-work cache** keyed on
    artifact_sha256 + provider_version + method_version + params,
    **incremental deltas** (v17 + Delta → v18), **reproducibility bundles**.
13. **Analysis ≠ Modification correctness** — two separate validation
    pipelines; never auto-promote analysis confidence into modification
    confidence. Baseline round-trip before patching a hard APK.
14. **Benchmark Vibe itself** — fixtures A–F (simple Java, multi-DEX, JNI,
    stripped native, obfuscated DEX, dynamic loading) + known questions
    (find string/resource owner, callers, JNI target, native XREF, CFG,
    map, runtime) measured on target precision/recall, entity-mapping
    precision, evidence correctness, false claims/conflicts, unknown
    recognition, wall/CPU/RAM, provider+LLM calls, cache hit rate. This is
    the only way to prove "smarter" vs "bigger".

Revised /360 priority (supersedes the older P0–P18): P0 CI + regression
foundation, P1 Toolchain doctor (PR #5), P2 APK/Manifest/Resource/DEX/Native
IR, P3 LocationResolver, P4 Search + TargetFinder, P5 RadareProvider, P6
Dex/Smali/JADX Provider, P7 JNI Resolver, P8 Ghidra escalation, P9
EvidenceGraph, P10 Code360+CodeTransparent, P11 MethodKnowledge, P12
Unknown/Hypothesis/EvidenceGain planner, P13 multi-agent protocol +
blackboard, P14 Commander + specialists, P15 Evidence/Falsifier, P16 Frida,
P17 static↔runtime, P18 Vibe Memory + AttemptLedger, P19 Research + MethodLab,
P20 Telegram controller, P21 WorkingCopy+ChangeSet, P22 rebuild/align/sign/
verify, P23 ADB/emulator validation, P24 benchmark+regression corpus,
P25 self-improvement eval.

### Mapped to what's already on the branch (as of this note)
- **P2 (IR)** — DONE in this branch as the Vibe IR: `tools/vibebot/graphutil.py`
  (stable A/C/M/F/S/R/N/K IDs, reproducible per SHA-256, `/apk` overview card,
  `/map` tree + cross-layer paths, string S-corpus = full DEX string table,
  honest JNI boundary).
- **P9 (EvidenceGraph) — partial**: the session store now MERGES engine
  layers (union structural + findings-by-id + intake), so `/apk` + `/dex` +
  `/analyze` on one SHA compose into one growing graph instead of clobbering.
  That was a real latent bug (upsert previously overwrote `structural`).
- **P3 (LocationResolver)** — the graph carries the DEX-side location chain
  (A1 → dex → class C → method M → string S refs); native-side location
  (.so → .text → N → B → I) is the next step (needs Radare/ELF provider).
- **P4 (Search + TargetFinder)** — DONE: `/find <text> --sha <…>` runs
  resource → DEX-string → reference → class/method ownership over the IR,
  returns T-ids with location chains + E-level/claim + honest no-match.
- **canonical EntityResolver (P0-level)** — DONE: `graphutil.resolve_entity`
  maps provider entities → canonical ids via the six mapping states
  (EXACT/STRONG/PROBABLE/AMBIGUOUS/CONFLICT/UNRESOLVED); enforces
  "never merge PROBABLE as EXACT" + "fp match w/ different name = CONFLICT".
  The contract future Radare/JADX/Ghidra providers route through.
- **P3 (Evidence + Claim model)** — DONE: `tools/vibebot/claims.py` derives
  first-class Claim objects (pure, deterministic) from the IR + DEX
  byte-integrity: E1–E5 strength table (what each *can* establish), 6
  CodeTransparent categories, 7-state machine enforced by `transition()`
  (no skipping — "Found" never silently becomes "proved"), `/claims` board
  + `/why` CLAIM→EVIDENCE→REF→ARTIFACT trace. NOT OBSERVED ≠ IMPOSSIBLE
  (orphan strings PROPOSED; native = "backing .so NOT OBSERVED"); coverage
  is a statement, never a fake confidence %. 172 checks.
- **P6 (CapabilityRouter + AnalysisBudget/stop-controller)** — DONE:
  `tools/vibebot/router.py` = live provider registry (honest detection) +
  METHOD_CATALOG (cheapest-capable ranking by evidence/cost, unavailable
  degrades honestly) + Budget (wall/calls/depth + stall detector) +
  watchdog for non-cooperative engines. `core.Job` enforces the budget at
  every progress/checkpoint; `JobManager._run` wraps each engine in the
  watchdog; `/plan <goal>` + `/capabilities` + `--max-wall` flags. Every job
  now has a default 300s wall cap — nothing hangs. 194 checks.
- **P7 (/xref + /callers + /callees)** — DONE: `graphutil.xrefs()` resolves
  a canonical M-id OR dotted Class.method to incoming invokes (callers),
  outgoing invokes (callees) + referenced strings. Deterministic. External
  (non-in-APK) targets flagged EXTERNAL honestly (never faked in-graph);
  "no static xref" reported as such (absence != non-use). `/xref`
  `/callers` `/callees` wired. Completes /find → /xref → Used By/Uses.
  204 checks.
- **P10 (/investigate — orchestrated 18-stage)** — DONE:
  `tools/vibebot/deepdive.py` runs 01 Identity … 18 Summary as a bounded,
  cancellable JOB that reuses the Vibe IR + xref + claims + router under the
  P6 budget (per-stage progress → transport shows 01..18 live). Honest
  marks: deterministic stages ✓; native stages (11 Blocks / 12 CFG) "n/a —
  requires Radare/Ghidra" when absent; JNI carries "NOT OBSERVED !=
  IMPOSSIBLE"; 15 Unknowns lists exactly what was not established.
  `/investigate <path> [target]`; legacy synchronous `/deepdive` preserved
  (still used by mock tests). run_deepdive reproducible. 228 checks.
- **P5 (pluggable Radare native provider)** — DONE:
  `tools/vibebot/native.py` — r2 as a SUBPROCESS (never linked), wall-capped,
  with a RadareLike Protocol injection seam so every parser/resolver/matcher
  is unit-tested with a FakeRunner (CI runs it with NO r2 installed).
  LocationResolver (ELF64 va<->file-offset, honest "approx" flag),
  provider-version provenance, JNI bridge via the UNIQUE underscore form
  (missing export = NOT OBSERVED, never a fake bridge), resolve_native_entity
  maps r2/ghidra/Frida entities to canonical N-ids via the SAME six-state
  EntityResolver. /native <path> (job): .so direct or APK .so extraction;
  degrades to a COMPLETED "not installed — NOT OBSERVED" marker. 252 checks.
- **P0 (CI + regression)** — DONE (this branch's half): `2925d83` added a
  GUARDED step to `validate.yml` that runs PR #5's pytest suite when its
  test files exist on the tree (no-op here); verified on the combined tree
  (PR #5 head + VibeBot) that both suites pass together (252 + 45, no module
  collision). The `validate.yml` conflict at merge time is now de-risked;
  final resolution is a deliberate human choice at merge (Fatah).
- **P11 (Falsifier — deterministic mechanical refutation)** — DONE:
  `tools/vibebot/falsify.py` — after claims are derived, each falsifiable
  fact is re-checked against an INDEPENDENT reading of the graph (counts
  vs. lists; native-flag divergence between the two DEX passes in
  build_graph; dangling string refs; claim-level recounts of call edges /
  string refs / native nodes). Ported from ghidra-mcp's falsify.py +
  DOC_REFUTED pattern (study of bethington/ghidra-mcp, 2026-10-02).
  Severity-graded: tier1 hard contradiction moves the claim to CONFLICTED
  (or REJECTED if only PROPOSED) strictly via the claims.TRANSITIONS state
  machine — the falsifier challenges, never skips a state, never deletes;
  note-severity (e.g. framework/external call target) is advisory only.
  `/falsify [--sha]` command + FALSIFIER section appended to `/claims` +
  `[F1]` contradiction rendering in `/why`. Pure (no androguard), tested on
  synthetic clean + corrupted graphs (zero false positives / every
  corruption caught) + fixture e2e. 270 checks (+18).
- **P12 (cross-version method fingerprinting)** — DONE (v0.11, `f98beca`):
  `tools/vibebot/xmatch.py` — normalized DEX-bytecode fingerprint per method
  (ghidra-mcp `computeStrictHash` ported to DEX). The one DEX-specific
  adaptation: virtual registers are compiler-assigned and RENUMBERED between
  builds (unlike native x0/r0), so they're bucketed to REG; identity is kept
  in const-string literals, call targets, and small immediates (large
  bucketed to IMM_LARGE); branch targets collapse to L (kind survives,
  distance does not). Six-state matcher on the EntityResolver contract with
  an IDENTITY TIEBREAK for shared fingerprints (bare SHA-256 can't tell
  identical stubs apart — 14 fixture methods → 8 unique fps; tiebreak makes
  self-match 14/14 EXACT). Name tier keys on method NAME (not class.name —
  the class is usually renamed across versions too). `/xmatch <src> <dst>`
  runs as a job (two-APK parse under the watchdog budget), stores the board
  + matches in the session, emits CONFLICT/AMBIGUOUS as re-validation
  findings (only EXACT may carry a validated finding without re-validation).
  300 checks (+30); apkmod + redteam green; CI 36933967516.
- **P13 (obfuscated-enum detector)** — DONE (v0.12, `049e682`):
  `tools/vibebot/enumscan.py` — deterministic R8-shrunken-enum detector
  (lupoxyz technique #2). Signature: N `static` fields of the class's OWN
  type (instances hoisted out of the backing array) + a `values()`/`valueOf()`
  whose body builds an array (`filled-new-array` / `fill-array-data` /
  `new-array`). Graded verdict — `enum` (extends java.lang.Enum, E1
  un-shrunken), `shrunken` (the signature, E2), `partial` (self-fields but no
  array values()), `none` — PROBABLE ceiling (a patch-candidate list, never a
  claim the class IS an enum). Pure core over compact class records
  (unit-testable); thin androguard glue. Wired as a first-class `enum` node
  type (E-ids) in the Vibe IR: `/map` renders an ENUM DETECTION section,
  `/find` locates enums, `counts.enum` carries it. ALSO fixed a pre-existing
  bug: `graphutil` called `f.get_type()` (nonexistent in androguard 4.1.4 —
  it's `get_descriptor()`), so every field's type in the graph was silently
  `""`; now type-aware (the enum self-field logic depends on it). 310 checks
  (+10). Note: the fixture has NO enum (clean negative e2e: count 0, /map
  shows "none"); the positive case is covered by pure synthetic-record tests
  (a real shrunken-enum APK is the ground-truth to add, like xmatch's branch
  limitation).
- **P14 (hybrid / JS-layer detector)** — DONE (v0.13, `c52937c`):
  `tools/vibebot/hybridscan.py` — deterministic hybrid-app JS-layer detector
  (lupoxyz technique #4). Recognizes WHERE a hybrid APK keeps its REAL logic:
  uni-app (`assets/apps/_UNI_*/www/app-service.js`), Cordova (`www/cordova.js`),
  React Native (`assets/index.android.bundle`), Flutter (`flutter_assets/`,
  flagged as a `.so` — not a JS layer). Pure core (`classify` over ZIP entry
  names) = unit-testable on synthetic name lists; thin zip + DEX-bridge glue
  adds DEX-side signals (WebView instantiated, `addJavascriptInterface` /
  JsInterface use). Wired into `build_graph` as a `hybrid` layer: `/apk`
  overview gains a `logic layer` line, `/map` gains a full HYBRID / JS LAYER
  section with the "Patch the JS entry, not the smali" directive. NOT OBSERVED
  degrades honestly. Cordova's bare `plugins/` marker removed (would
  false-positive on any path containing `plugins/`). 322 checks (+12). Note:
  the fixture is a minimal native APK (no assets/), so the e2e verifies the
  NEGATIVE path; positive detection is covered by pure synthetic-name-list
  tests (uni-app/Cordova/RN/Flutter).
- **P15 (native function-pattern classifier)** — DONE (v0.14, `0b7c731`):
  `native.classify_function` recognizes a native function's LOGIC by its
  NORMALIZED ARM64 mnemonic SEQUENCE (not by hex bytes) — the durable form of
  lupoxyz's memorized hex-patch table. Six E3 flags (static disassembly
  evidence; PROBABLE ceiling): popcount-loop (clz+ror+eor), case-fold-scan
  (orr #32), bitset-test (tst …,lsl #imm), tbz-bit0-parity (tbz …#0/tbb),
  fused-madd (madd/mls), string-ref-pair (adrp+add :lo12:). Pure core;
  `parse_disasm` handles r2 pdj JSON (name + separate opcode field) and pd
  text (addr + 4 opcode bytes + mnemonic); wired into `/native` +
  `render_native` behind the RadareLike seam. TDD caught 2 real r2 output
  bugs (pdj operands in a separate field; pd opcode bytes before the
  mnemonic). 340 checks (+18). Honest limit: no r2/real .so on host —
  unverified against a real disassembly. Backlog #11 DONE.
- **P16 (native-harness validation)** — DONE (v0.15):
  `tools/vibebot/harness.py` + `/harness <srcdir>` — the top of the evidence
  chain: prove a native (ARM64) change BEHAVES via a C test harness under
  qemu-aarch64 (E5 runtime), never "the diff looks right". Build recipe is
  exercism-arm64 verbatim (NOT hand-rolled): cross-gcc/as, CFLAGS
  `-g -Wall -Wextra -pedantic -Werror -std=c99 -fPIE`, LDFLAGS
  `-pie -Wl,--fatal-warnings`, run under `qemu-aarch64 -L /usr/aarch64-
  linux-gnu` (direct on an aarch64 host). Pure core (`detect_toolchain`
  injectable, `build_cmd_*`/`run_cmd`/`parse_harness`/`validate_native`) +
  `HarnessEngine` (job; auto-discovers .c/.s in the srcdir; report JSON;
  E5 finding on SUCCESS/FAILURE, E0 NOT_OBSERVED otherwise). Verdicts
  SUCCESS/FAILURE/NOT_OBSERVED — NOT OBSERVED ≠ the change is wrong. 363
  checks (+23). Spec: `studies/2026-10-02-native-harness-validation-spec.md`.
  Honest limit: no qemu/cross-compiler on this host — real run NOT OBSERVED
  (the e2e asserts the degrade); SUCCESS/FAILURE via FakeRunner. Backlog #12
  DONE. Closes the loop P15→patch→P16.
- **P18 (v0.19) — real-radare2 6.x verification** — DONE (PR #6):
  first real r2 on the host (6.2.2 user-space). RadareRunner was never
  exercised beyond FakeRunner and was broken on r2 6.x (argv order, ANSI,
  iI→iij, pdj name→disasm, aXR→axtj, @hex vs decimal, PLT xref routing).
  All fixed dual-mode (r2-6 JSON + legacy text) and verified e2e on a real
  gcc .so. See studies/2026-10-02-p18-real-radare2-6.md.
- **P19 (v0.20) — real-ARM64 pattern e2e** — DONE (same PR #6): installed
  aarch64 binutils (user-space), committed `tests/fixtures/arm64/pat.s`
  (one fn per P15 idiom), built a real aarch64 .so, ran it through real r2.
  Exposed + fixed 3 classifier bugs: (a) `pdj {size}` counted BYTES as
  INSTRUCTIONS → disasm bled across functions and mis-attributed idioms
  (→ function-bounded `aa; pdfj @0xVA`); (b) P2 case-fold: r2 6 prints
  `orr …, 0x20` not `#32`; (c) P6 string-ref: r2 6 prints `adrp+add`
  without `:lo12:` (→ accept both, same-register). All 6 idioms now
  recognized on real ARM64, each on exactly its own function. 467 checks
  (457 CI shape). See studies/2026-10-02-p19-real-arm64-patterns.md.
  **P5/P15/P16 positive-e2e gaps: now CLOSED (x86-64 + aarch64).** Merge
  pending Fatah.
- **P14b (real-hybrid APK e2e)** — DONE (v0.20, same PR #6): P14's detector
  had only ever run on synthetic ZIP name lists + a native-only negative
  fixture. Built a REAL signed APK (aapt2 37.0 + d8 + apksigner, JDK17)
  carrying BOTH uni-app (`assets/apps/_UNI_*/www/app-service.js`) and Cordova
  (`assets/www/cordova.js`, `cordova_plugins.js`) layouts plus a real
  `@JavascriptInterface` WebView → committed `tests/fixtures/fixture-hybrid.apk`
  (13,058 B, reproducible; recipe in scratch). scan_artifact on it detects
  both frameworks with the right real markers, lists the real js_entries, and
  `webview_used=True` from REAL DEX (`invoke-virtual WebView →
  addJavascriptInterface`, E2) — the DEX path P14 had never exercised.
  `jsinterface=[]` pinned as honest (the bridge method is called from JS at
  runtime, never from DEX). +6 checks → 473 (463 CI shape; fixture committed
  so it runs there too). See studies/2026-10-02-p14-real-hybrid-apk.md.
- **P17 (Kotlin @Metadata name recovery)** — DONE (v0.16, backlog #2):
  `tools/vibebot/kotlinmeta.py` + `/kmeta <classes.dex|app.apk> [class_filter]`.
  R8 renames every DEX name, but a Kotlin class's `@kotlin.Metadata` annotation
  carries the ORIGINAL names: `d1` (BitEncoding-encoded proto) + `d2` (string
  table with the real identifiers). This build: (a) pinned a **ground-truth
  fixture** `tests/fixtures/ktmeta/classes.dex` (kotlinc 2.0.21 → d8, known
  identifiers: CheckoutService/charge/gateway/totalCents/Companion/Order.Paid);
  (b) implemented the decoder in **pure Python** from the authoritative
  JetBrains source (fetched, not memory): `BitEncoding.decodeBytes` (UTF-8 mode
  = drop U+0000 marker + char→byte; 8-to-7 mode), `JvmProtoBufUtil` layout
  (StringTableTypes delimited + Class message), `JvmNameResolverBase.getString`
  (string/predefined-index/desc-operations) + the full PREDEFINED_STRINGS table;
  (c) **differentially verified** the pure decode against the **Kotlin
  compiler's own deserializer** (`tools/vibebot/KMeta.java`, subprocess over
  kotlin-compiler.jar — license-safe, subprocess-isolated like P5/P16):
  pure==oracle on all 6 fixture classes. TDD caught 2 real bugs: packed-int32
  `nested_class_name` (field 7) parsed as tagged subfields (dropped the
  Companion), and primitive annotation elements read via `.value_arg` (0)
  instead of `.value` (dropped k/mv/xi). Envelope: k=1 (CLASS), mv=[2,0,0],
  xi=48; **d1 is NOT base64** (the old study note was wrong for Kotlin 2.x).
  E2/PROBABLE ceiling (recovered names are the source's intent; re-validate
  against behavior before acting). 385 checks (+22). Backlog #2 DONE.
  Honest limits: single-fixture coverage (one kotlinc 2.0.21 / d8 shape —
  8-to-7 mode unexercised by a real sample; un-marked d1 is a documented
  fallback); oracle cross-check only runs where a Kotlin toolchain is present
  (NOT OBSERVED elsewhere, never a fake pass). Design origin:
  `studies/2026-10-02-external-study-lupoxyz-ghidra-mcp.md` (backlog item 2).
- ~~Kotlin @Metadata name recovery~~ — DONE above (P17, v0.16); the
  "STILL DEFERRED" state was unblocked when scratch gained JDK17 + kotlinc +
  d8, and the message-level proto numbers from `metadata.proto` were verified
  against real compiler output end-to-end.

- **v0.17 hardening batch (lupoxyz #6/#7/#8/#10)** — DONE (v0.17):
  closes the remaining host-buildable lupoxyz backlog items in one batch.
  - **#6 file-root containment** (GHIDRA_MCP_FILE_ROOT pattern):
    `Gateway(file_root=…)` / `VIBE_FILE_ROOT` env, **opt-in** — unset keeps
    current no-gate behavior (no test/deploy churn), set gates all 13
    path-accepting handlers through `_artifact()`. Outside-root and `../`
    escape → refused ("outside the file root … NOT OBSERVED"); missing
    inside-root path still reports not-found.
  - **#7 /investigate gap split** (B3): `deepdive.classify_gaps` (pure)
    separates **actionable** gaps (native stages 11/12 — install r2/ghidra
    + re-run; a tool install is an action) from **unobservable** gaps
    (runtime/data-boundary — NOT OBSERVED != IMPOSSIBLE); rendered under the
    card. Pure over the result dict (unit-testable, no androguard).
  - **#8 L0/L1 command split + searchable registry** (B4): `registry.py` is
    the single source of truth (tiered: L0 always, L1 searchable) with
    `/commands [query]` keyword search. /help stays short and intact (tests +
    live menu depend on it); the surface is now >20 so the split is warranted.
  - **#10 invariant tests**: asserts no "most recent session" fallback
    (`/find`/`/xref` without `--sha` are refused, last-job sha is only a hint)
    and version-string consistency — `__init__.__version__` bumped to `0.17.0`
    (it had been stuck at `0.1.0` through v0.16 — this is the invariant that
    was actually lagging).
  407 checks (+22). apkmod + redteam 32/32.
- **v0.18 Frida oracle gating (lupoxyz #9)** — DONE (v0.18): the LAST open
  study-backlog item, now closed. `studies/2026-10-02-frida-oracle-gating-spec.md`
  (the "design note before any Frida work") + `tools/vibebot/oracle.py` (pure
  gating core) + read-only `/oracle` dry-run command. The gate encodes the
  study's safety rationale — a wrong call that crashes is cheap, a wrong call
  that RUNS is not — as four rules: (1) OFF by default (`VIBE_ORACLE_CALL`),
  (2) named-exports only (raw/absolute address refused), (3) differential
  needs a named reference on both sides, (4) fail closed → NOT OBSERVED. The
  Frida *runtime call* is intentionally NOT implemented (no Frida on this
  host) — the gate is the deliverable; the future runtime worker calls
  `oracle.decide()` first and only spawns a budgeted hook if allowed. 430
  checks (+23). apkmod + redteam 32/32. **The lupoxyz study backlog is now
  fully DONE (items 1–10).**

- **P0 merge-proof re-verified (v0.18 head 6e07a42)** — re-ran the combined-tree
  proof at PR #5 head `de431429` + VibeBot v0.18 in a detached worktree:
  Anam's **full 10-file** pytest suite = **59 passed**; our suite = validate.py
  OK + redteam 32 + apkmod ALL PASS + vibebot ALL PASS; the 5 shared
  `tools/{redteam,redteam_test,apkmod,apkmod_test,validate}.py` and
  `fixture-demo.apk` are **identical** on both branches; **no module-name
  collisions** (`tools/vibebot/*` vs `tools/vibe_*.py`). **The ONLY real
  conflict is `validate.yml`.** Found + FIXED a silent-CI-loss bug: our
  `validate.yml` pytest step listed only 8 of PR #5's 10 test files (omitted
  `test_vibe_artifact_router.py` + `test_vibe_correlation.py`) — resolving the
  merge toward our unfixed file would have dropped those 2 suites. The step now
  runs all 10 (true superset), re-verified 59-passed. **So: resolving the
  `validate.yml` conflict toward OUR branch is now provably safe** — the merge
  is Fatah's call, no longer a P0 risk.

## Open items (need Fatah/Anam decision)

1. **Bot identity** — new Telegram bot via BotFather (token never
   committed; allowlist of user ids required before any public use).
2. **Hosting** — where `--serve` runs (this host? dedicated container?),
   uptime expectations, storage for session artifacts.
3. **P2 engine scope** — DEX Mapper depth (full call graph vs.
   chokepoint-focused, the latter matches the current fingerprint DB).
4. **Real-APK validation** — run VibeBot against an authorized
   third-party APK to validate the apkmod adapter's evidence on real DEX
   (fixture validation done; real-world still open from v1.3.0).
5. **License hygiene** — before any REUSE of RevEngi-ecosystem code
   (java2smali MIT etc.), record license + attribution in sources.md.
