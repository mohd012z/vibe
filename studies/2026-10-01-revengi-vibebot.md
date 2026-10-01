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
- **P2 (next)** — DEX Mapper + Smali Inspector engines: class → method →
  reference map as first-class outputs; smali grammar from `smalig`
  (MIT, 257-instruction yaml — track upstream, CI-sync pattern); DEX
  repair salvage in INTAKE (magic 035-040, SHA-1@12, Adler-32@8 LE —
  portable algorithm from revengi-app, reimplemented, ~15 lines);
  `/graph` rendering, search over the evidence graph
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
