# VibeBot — native toolchain install (activate P5 providers)

The VibeBot vertical slice is **androguard-only** on this host: `doctor`
reports only androguard present; `r2`/`jadx`/`apksigner`/`adb` are absent.
Every native-dependent command therefore degrades **honestly** to
"NOT OBSERVED / not installed" (never a fabricated result). This doc is the
exact, pinned set of installs that turn those honest degradations into real
analysis **without changing any VibeBot code** — the `RadareLike` provider,
router registry, EntityResolver, and LocationResolver already exist and light
up the moment the binaries appear on PATH.

Source of versions: PR #5 `toolchain/android-tools.json` (the team's own pin
list). Do NOT install ad-hoc versions — the providers record
`provider_version` provenance on every result, and the plan pins these:

| Provider  | Binary / package        | Pinned   | Enables (VibeBot)                              |
|-----------|-------------------------|----------|------------------------------------------------|
| radare2   | `r2`                    | 6.2.x    | `/native`, `/investigate` stages 11 (Blocks) + 12 (CFG), XREF E3 |
| jadx      | `jadx` (needs JDK)      | latest-stable | readable reconstruction (E1), JADX provider |
| apktool   | `apktool` (needs JDK)   | 3.0.3    | resource decompile, `/plan` apktool method     |
| smali     | `smali`/`baksmali` (JDK/Maven) | 3.0.7 | dex dis/assemble + dexlib2 (programmatic)      |
| build-tools | `apksigner`/`zipalign`/`adb` (via `sdkmanager`) | sdkmanager-managed | P21+ signing, P23+ runtime (modify path, deferred) |

## 1. What actually activates what
- **`r2` alone** → `/native <.so|apk>` produces real ELF functions / imports /
  exports + LocationResolver chains; `/investigate` stages 11/12 move from
  `n/a` to real; the EntityResolver can map r2 `fcn.xxxxx` → canonical N-ids.
  This is the single highest-value install (native vertical slice).
- **`jadx` (+JDK)** → readable reconstruction (JADX ≈ *reconstructed readable
  representation*, still NOT original source — VibeBot never claims otherwise).
- **`apktool` (+JDK)** → resource decompile for the `/plan resource` method.
- **`adb`/`frida`** → runtime layer (P12/P17, E5 "observed in ONE run").

## 2. Install (this host: Linux, `uv` for Python, no root assumed)
> Each is optional and independent. Verify with the VibeBot's own detection
> after each install — do not trust "installed" on faith.

### radare2 (highest value)
```bash
# from source (stable, reproducible) or the team's pinned 6.2.x
# quick check after: r2 -v  must print a 6.2.x version
r2 -v
```
VibeBot detects it via `shutil.which("r2")`. No code change needed.

### JDK + jadx + apktool (needed together)
```bash
# JDK 17 (headless) first — jadx and apktool both require java
java -version
# then jadx and apktool per the pinned versions in android-tools.json
jadx --version
apktool --version   # must be 3.0.3
```

### Verify via VibeBot (the honest gate)
```bash
/opt/data/cache/scratch/vibe-study/.venv/bin/python - <<'PY'
import sys; sys.path.insert(0, "tools")
from vibebot import router
print(router.detect_providers())
PY
```
You should see `radare2: True` / `jadx: True` / `apktool: True` for whatever
you installed. Then:
```
/native <a .so>            -> real functions/imports/exports (was NOT OBSERVED)
/investigate <apk> <M-id>  -> stages 11/12 populated (was n/a)
```

## 3. Invariants that MUST hold after install
1. **Subprocess isolation** — r2/jadx/apktool are spawned as subprocesses,
   never linked/imported. A JVM tool crashing cannot take down the Python bot.
2. **Budget** — every provider run is wrapped by the P6 `Budget` (wall cap +
   watchdog). A hung `r2` on a large binary is abandoned, not a stuck queue.
3. **Provenance** — each result carries `provider_version`; if a tool is
   upgraded and its output semantics change, old results stay honest (they
   record the version that produced them).
4. **Honest degradation stays** — if a provider is later removed, the command
   degrades back to "not installed" rather than erroring or faking.

## 4. NOT in this doc (out of scope)
- **Build/modify path** (apksigner/zipalign + rebuild) — deliberately deferred
  to P21 (the `/patch-plan --authorized` working-copy workflow). Installing
  apksigner alone does not enable modification; the whole rebuild/verify loop
  must be built first.
