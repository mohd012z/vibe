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

## Org inventory (as surfaced by Anam, 2026-10-01)

- `docs` — official RevEngiBot documentation (TypeScript/Next.js, MIT
  claim) — command → engine → result map.
- `revengi-app` — main all-in-one Dart app (MIT claim) — architecture
  reference for module/parse layout.
- `yarax_android` — YARA-X Android integration (Rust, BSD-3 claim).
- `PineHookPlus` — **runtime hooking research** (config-driven
  class/method/param/action descriptors; auto ARM32/ARM64 library select).
  Different domain: runtime modification vs. static analysis.
- Conversion utilities outside the org by the same developer:
  understand-smali, smalisp, smalig, java2smali (uses d8, MIT claim),
  Fine, pyxamstore, LYADI.
- Forks (not original RevEngi tech): garlic, catcher_2, kterm.dart,
  dataset, installed_apps, ApkDataMultiplex — classified accordingly.

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
- **P2 (next)** — DEX Mapper + Smali Inspector engines (class → method →
  reference map as first-class outputs), `/graph` rendering, search over
  the evidence graph
- **P3** — native ELF/JNI inventory engine, Flutter detector engine
- **P4** — Telegram deployment (token + allowlist + hosting decision),
  `/diff` engine (two builds), YARA-style rule engine (license check first)
- **P5 (separately gated)** — conversion adapters (java2smali-class, d8
  based), AI correlation layer on normalized findings, runtime observation
  stage (authorized targets only)

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
