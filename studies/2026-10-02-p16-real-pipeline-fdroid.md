# P16 real pipeline e2e — F-Droid whole-APK orchestration + deepdive graph-shape fix (v0.26)

Date: 2026-10-02 · Branch: feat/deepdive-graph-session (PR #27) · Author: Aliph
(Anam-directed "proceed" sweep, Fatah notified; orchestration layer on real data)

## Gap this closes

v0.24 (DEX) and v0.25 (native) verified the COMPONENTS on real production data.
This round verifies the ORCHESTRATION layer: the full gateway pipeline
(`/apk` ingest → Vibe IR graph → `/find` `/map` `/claims` → `/investigate`
18-stage) running end-to-end on the real F-Droid client APK — the first time
the whole pipeline has touched a real (non-synthetic) artifact.

## Real-APK pipeline run (facts)

`/apk F-Droid.apk` (12,537,183 B, sha256 83d3fe52…) on the production gateway:

- Ingest: **215.5s** (24,520 classes, 129,118 methods, 59,319 fields,
  128,736 strings, **475,990 call edges** — the scale tier no synthetic
  fixture has ever reached; all prior e2e fixtures were ≤13KB).
- All 3 DEX pass integrity (magic/version/size/adler32/sha1).
- Hybrid detection correct: `webview_used=true`, `jsinterface=[]` (F-Droid
  renders its UI in WebView but exposes no JS bridge), `js_entries`
  `assets/index.template.html` — a real positive that a false-positive-prone
  detector could get wrong.
- `/map` / `/find` / `/claims` on the session: 24,570 claims with proper
  E-levels (38 VALIDATED / 19,926 SUPPORTED / 4,605 REPRODUCED / 1 PROPOSED
  / 2 CONFLICTED), cross-layer component→class→method paths present
  (K3 org.fdroid.MainActivity → M111936/M111937).
- `/investigate F-Droid.apk org.fdroid.MainActivity.onCreate`: 18 stages,
  **15/18 established** in 64.8s; 07 Callees shows real invoke edges
  (Hilt_MainActivity.onCreate [invoke-super], Compose setContent, etc.),
  08 Data shows real fields (notificationManager, settingsManager,
  requestPermissionLauncher), 11/12 (Blocks/CFG) honestly `n/a` — r2 not on
  PATH in this run + the target is a DEX method (not a .so); `NOT OBSERVED
  != IMPOSSIBLE` note present.
- **Scale observation (not a bug):** the stored session is **274 MB** (the
  full graph incl. 475,990 call edges + 24,570 claims is persisted JSON).
  Fine for analysis; would be a problem for the Telegram bot path or a
  multi-session host. Recorded as a future concern (session compaction /
  on-demand edge materialization), not fixed here.

## Finding — `/deepdive` dead on graph-engine sessions (the bug)

`/deepdive org.fdroid.MainActivity.onCreate --sha 83d3fe52…` returned
**0 matches** on the real session — for a method that IS in the stored
graph (M111948). Root cause (schema split, verified): `core.deepdive()`
only traversed the **dexmapper/apkmod** session shape (`structural.calls`,
`structural.jni`, `structural.nativeLibs`), while the graph engine stores
everything under `structural.graph{nodes{method,class,native,…},
calls[], library_files[]}`. The flat keys don't exist on graph sessions,
so every branch saw empty lists. The 18-stage `/investigate` was unaffected
(it reads `structural.graph` directly) — which is why the two commands
disagreed on the same session: one said "M111948 exists", the other said
"no stored matches — run /analyze first" (a **false** hint: the scan HAD
been run).

Same gap class as v0.24/v0.25: the bug was invisible because every test
session in the suite was dexmapper-shaped (mock engine); only a
graph-engine session — i.e. only a real `/apk` run — exercises the other
shape.

## The fix

`core.deepdive()` now traverses BOTH shapes (additive, dexmapper behavior
unchanged):

- graph `nodes.method` → substring + `Class.method` resolution (via=`method`,
  carries the M-id in detail);
- graph `calls[]` → the `callers` / `calls` / substring branches (same edge
  shape as dexmapper — caller/callerMethod/targetClass/targetMethod/invokeKind);
- graph `nodes.native` + `library_files` → the `native`/`jni` branch;
- the zero-match note is now engine-aware: a graph session reports
  "no match in the stored graph (traversed N methods, M call edges —
  target not present in this artifact)" — a REAL negative, not the
  misleading "run /analyze first".

## Verification

- **Real F-Droid session (274 MB, production shape):**
  - `MainActivity.onCreate`: 0 → **28** matches (M-ids, via=`method`);
  - `MainActivity` (class substring): **168** matches;
  - `callers`: **475,990** (every stored edge);
  - `native`: **8** (the real JNI nodes);
  - `zzz.not.present`: 0 with the new real-negative note.
- +6 pure unit checks on a minimal graph-shaped synthetic session
  (resolution, class-substring, callers, calls, native, real-negative).
  Dexmapper-shape checks all still pass (additive fix proven non-breaking).
- 506 full-host / 493 CI-shape ALL PASS, redteam 32/32, apkmod ALL PASS.

## Honest limits

- The 274 MB session file is a real scale fact, disclosed not fixed
  (compaction is a separate piece of work; nothing breaks today).
- `/deepdive callers` on a real graph session returns ALL 475,990 edges
  (the gateway reply caps at 25 + "…N more", so the user-facing output is
  bounded; the matchCount is intentionally the full count).
- Stages 11/12 (Blocks/CFG) on a DEX method target are n/a by definition
  (they need a .so); on a native N-node target with r2 on PATH they would
  run — not exercised in this round (the F-Droid JNI surface is the small
  AndroidX path lib).

## Methodology note

Third time the same lesson has bitten: **a production-shaped input exposes
what the fixture shape cannot** — wide string indices (v0.24), PLT
trampolines (v0.25), and now a second session SCHEMA (v0.26). The /360
rule "validate against real production artifacts" is now the single most
productive instruction in this repo.
