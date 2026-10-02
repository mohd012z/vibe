# P14 — real-hybrid APK e2e (v0.20, folded into PR #6)

Date: 2026-10-02 · Branch: feat/native-r2-verified (folded) · Author: Aliph (Anam-directed "contineu pending")

## Gap this closes

P14 (hybrid/JS-layer detector) had only ever run on **synthetic ZIP name
lists** (pure `classify()`) plus the *native-only* `fixture-demo.apk` negative
control. Its study note disclosed: *"a real uni-app/Cordova/RN APK is the
ground-truth to add."* That is the same FakeRunner-only positive-e2e gap class
as P15 (native patterns) and P5/P16 — the detector's DEX-touching path
(`webview_used` / `jsinterface` via `dexmapper`) had **never** executed against
a real `classes.dex` from a genuinely built APK.

## What was built (real toolchain, user-space)

A real, **signed** APK carrying *both* known JS frameworks plus a real
`@JavascriptInterface` WebView:

- `aapt2 link --manifest AndroidManifest.xml -I android.jar`
  (build-tools 37.0, JDK17, android-35 android.jar) → valid APK shell
- `javac -source 11 -target 11 -cp android.jar` → `d8 --min-api 21`
  → `classes.dex` (real DEX, not handcrafted)
- assets zipped in with the exact framework layouts:
  - Cordova/PhoneGap: `assets/www/index.html`, `assets/www/cordova.js`,
    `cordova_plugins.js`
  - uni-app: `assets/apps/_UNI_69070101/www/app-service.js`,
    `assets/apps/_UNI_69070101/www/app-view.js`
- `zipalign -f 4` + `apksigner sign` (v3, self-signed 2048-bit RSA, CN=Vibe
  Fixture) → `tests/fixtures/fixture-hybrid.apk` (13,058 bytes,
  reproducible across runs)

Build recipe kept OUT of the repo (scratch):
`/opt/data/cache/scratch/hybrid-build/build_hybrid_apk.sh`.

Toolchain gotchas found while building (all on build-tools 37.0):
- `d8 --output <dir>` requires the dir to exist → `mkdir -p` first.
- aapt2 37.0 has **no `add` subcommand** (help lists compile/link/dump/diff/
  optimize/convert/apkinfo/daemon) → assets added via Python `zipfile` append.
- `aapt2 link` wants an explicit `--manifest` (not a bare positional) and has
  no `--align` (that's `zipalign`'s job).
- No `zip` binary on host → `zipfile.ZipFile(ap, "a")` append; DEX entry name
  must be exactly `classes.dex`.

## What the real DEX proved through the detector

`hybridscan.scan_artifact("tests/fixtures/fixture-hybrid.apk")`:

- `frameworks`: **uniapp** AND **cordova** both detected, each with the right
  real markers (`_UNI_` paths; `assets/www/cordova.js`).
- `js_entries`: the real JS-layer files (`app-service.js`, `index.html`, …).
- `webview_used: True` — from REAL DEX: `dexmapper` captured
  `invoke-virtual android.webkit.WebView -> addJavascriptInterface` (E2).
  This is the DEX path P14 had never exercised.
- `jsinterface: []` — **correct and honest**: the `@JavascriptInterface`
  method `Bridge.ping()` is called from JS *at runtime*, never from DEX, so a
  static DEX scan must not claim it. (Kept as a pinned assertion so a
  future over-claim fails loudly.)

## Test added

`tools/vibebot_test.py` — P14 block, after the native-fixture e2e, guarded by
`HAVE_ANDROGUARD` and self-degrading: if `fixture-hybrid.apk` is absent on a
host, it prints an honest NOT OBSERVED line (never a red check). Six new
checks (both frameworks, markers, js_entries, real-DX `webview_used`,
honest `jsinterface`).

## Result

- Full host: **473 checks ALL PASS** (was 467; +6 real-hybrid).
- CI shape (no r2): **463 checks ALL PASS** — fixture is committed, so the
  6 real-hybrid checks run there too (androguard present); r2 e2e blocks
  degrade to honest NOT OBSERVED.
- redteam 32/32, apkmod ALL PASS (unchanged, regression gate).
- `__version__` stays **0.20.0** — this round is tests + fixture only
  (no `vibebot/` runtime change), so no bump.

## Honest limits

- The APK is a **synthetic-but-real** build: genuine aapt2/d8/apksigner output
  and genuine framework layouts, but the JS payloads are tiny stubs — it proves
  the *detection* path, not behavior of a production uni-app/Cordova bundle.
- `webview_used` is E2 (DEX invoke), not E5 (runtime) — no device/emulator.
- Only uni-app + Cordova layouts are fixtured here; RN (`index.android.bundle`)
  and Flutter are still covered by pure-name-list classify checks (their
  marker logic is unchanged and DEX-independent).
