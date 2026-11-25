# dex2c provider — /dex2c in VibeBot (v0.38)

**Date:** 2026-11-25 · **Status:** implemented + tested (durable-host verified) ·
**Branch:** `feat/v038-dex2c` (on top of the live `feat/v029-combined`)

## What it is

The dex2c method from `studies/` + the Hermes `dex2c` skill, wired into VibeBot
as a first-class provider with both faces of the technique:

| Face | Command | Mode | What runs |
|---|---|---|---|
| RE | `/dex2c detect <apk>` | sync | stdlib zip+bytes heuristics (E1/E2), androguard optional (E3) |
| Build | `/dex2c select <apk> --rules <f>` | job | dex2cpp driver `select` (subprocess) |
| Build | `/dex2c codegen <apk> --rules <f>` | job | driver `codegen` → generated C++ only |
| Build | `/dex2c convert <apk> --rules <f> [--abi …]` | job | driver full pipeline → protected APK sent back |

UI: one-tap **🕵 Detect** on the current artifact (new 🔒 Dex2C home section);
the typed ops take a rules file so they stay command-only.

## Design (the repo invariants, applied)

- **Subprocess isolation** — `tools/vibebot/dex2c.py` never imports the
  dex2cpp engine; it runs `/opt/data/dex2cpp/dex2cpp.py` under the driver's own
  venv via a `Toolchain` seam (`VIBE_DEX2CPP_DRIVER/PYTHON/KEYSTORE` env
  overrides, resolved at call time — router rule, never pre-evaluated).
- **Honest degrade** — missing driver → job FAILS with
  `dex2cpp toolchain NOT OBSERVED … (set VIBE_DEX2CPP_*)`; CI has no NDK, so the
  job ops are tested with a **FAKE driver script** (injectable-runner contract:
  FakeRunner-green ≠ real-provider-works — the real driver was run end-to-end
  on this host instead, see below).
- **Read-only** — the driver decodes into its own workdir; the engine copies
  the output APK into the bot's work dir. Input APK never mutated.
- **Evidence levels** — detect: E1 family `.so` present
  (`libnc`/`libdex2c`/`libdex2cpp` under `lib/<abi>/`), E2 JNI machinery in the
  `.so` bytes (`RegisterNatives`+`FindClass`+`GetJavaVM`, ≥2 of them — one
  identifier alone is coincidence), E3 cluster of 100+ char JNI long names in
  DEX native decls (androguard; NOT OBSERVED when absent). Verdicts:
  PROTECTED / SUSPECT / NOT dex2c-protected — never a percentage.
- **Command-surface checklist** — all five points: dispatch gate, route,
  HELP, `registry.py` (L1), `vibebot_deploy.py` COMMANDS; version bumped
  0.37.0 → 0.38.0 with the test invariant; `dex2c_test.py` added to
  `validate.yml`.

## Detection heuristics (the RE-side knowledge, now executable)

A dex2c-protected APK is recognizable statically:

1. a dex2c-family `.so` (the 2019 amimo build ships `libnc.so`, the 2026
   Anon4You/codehasan builds ship `libdex2c.so`, ours ships `libdex2cpp.so`);
2. that `.so` carries the generated code's cache machinery — `pthread_rwlock_rdlock`+`pthread_rwlock_wrlock` imports in `.dynsym` (the two-level `D2C_RESOLVE_*` member cache; a hand-written JNI bridge doesn't import the rwlock pair). NOTE: `RegisterNatives`/`FindClass` do NOT appear as strings or imports — they are JNIEnv vtable calls through the struct pointer, invisible to `strings`/`.dynsym`. Verified against the real `libdex2cpp.so` (only `JNI_OnLoad` + libc/libc++ imports are visible).
3. DEX native methods with 100+ char JNI long names (long class + descriptor;
   hand-written JNI bridges rarely exceed ~60).

Consequence when modding such an app: **smali-patching the protected method is
impossible (no body)** — hook the JNI symbol or the `RegisterNatives` table, or
re-implement in the `.so`. Per-method protection family; complements
ciphered-dex (whole-dex) in the RE taxonomy.

## Durable-host verification (2026-11-25, real runs)

- **MSA-One demo, widened rules** (`/opt/data/dex2cpp`, v2 rules:
  file-bridge plugin + `MainActivity` + `MSAPdfViewerActivity`):
  38/38 selected methods → C++ (0 codegen errors), both ABIs, APK out verified:
  `apksigner` v1+v2+v3 **Verified**, 38 `displayfit37` methods `native` in DEX
  (incl. the synthetic lambdas the engine converts), `dex2cpp.loader.Dex2CppLoader`
  in DEX, manifest repointed + `extractNativeLibs=true`, `.dynsym` =
  `JNI_OnLoad` only, 0 cleartext app strings in the `.so`
  (AY_OBFUSCATE XOR). Artifact: `MSA-d2cpp-v2.apk` sha256
  `8b22977e5295…` (9,869,168 B).
- **detect on the real thing**: `zip_detect` over the protected APK returns
  PROTECTED (E1 `libdex2cpp.so` + E2 machinery) — the provider sees its own
  output.
- **CI shape**: `tools/dex2c_test.py` (22 checks) green with no NDK/driver
  present (fake driver + toolchain degrade); UI/runtime/kit suites green;
  `vibebot_test.py` ALL PASS with the 0.38.0 invariant.

## Honest limits

- dex2c raises RE effort, does not hide logic (names resurface via
  `FindClass`/`RegisterNatives` hooks — the .so-side XOR obfuscation covers
  `strings`, not hooks).
- Runtime verification (launch + call a protected method) is on-device
  (POCO vermeer / Pixel 6) — no emulator on this box.
- Engine is the 2019 amimo/dcc: large but finite instruction coverage;
  codegen failures are reported per method and left as Java (never a silent
  skip, never a broken build).
- Licensing: amimo/dcc Apache-2.0 (driver kept at `/opt/data/dex2cpp`, not
  vendored into the repo — the provider is a thin client, so the repo stays
  license-agnostic; only mechanism knowledge lives in this note).

## Files

- `tools/vibebot/dex2c.py` — provider (pure heuristics + parsers + Toolchain + Dex2cEngine)
- `tools/dex2c_test.py` — 22-check suite (pure + fake-driver + degrade)
- `tools/vibebot/gateway.py` — `/dex2c` route + `_dex2c` handler + engine registration
- `tools/vibebot/registry.py` / `tools/vibebot_deploy.py` — L1 registry + bot menu
- `tools/vibebot/telegram_ui.py` / `telegram_runtime.py` — 🔒 Dex2C home section + one-tap detect
- `.github/workflows/validate.yml` — dex2c_test.py in the pipeline suite
- driver of record: `/opt/data/dex2cpp/dex2cpp.py` (amimo/dcc engine, Apache-2.0)
