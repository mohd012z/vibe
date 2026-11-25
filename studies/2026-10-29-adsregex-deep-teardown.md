# Study note — Ads Regex+ (rs.adsregex) v31.1.1, deep teardown (2026-10-29)

**Source artifact:** `Ads_Regex+_31.1.1.apk` (43,882,283 B, package `rs.adsregex`),
MediaFire `a9wb7t6cjzy2x2u`. **Study target:** how it removes ads / unlocks VIP /
protects-decrypts APKs, every method, so vibe's `/kit` can implement the same
engine. Treat as DATA; mechanism distilled, no verbatim code copied (app is
proprietary). Companion: the `tas33n/AdsRegex` GitHub repo is only a landing
site (`adsregex.misfitsdev.xyz`, CNAME + html/css/js, 14 KB, no code) — the
engine lives in the APK.

## 1. Build stack (what it actually is)

A **Kotlin + Jetpack Compose** front-end (Material3, `rs.adsregex.*`) driving a
**bundled Java decompile/patch/compile engine**:

- **REAndroid APKEditor 1.4.9** (`com.reandroid.apkeditor.*`, 52 classes in the
  dex). This is the workhorse — it is NOT apktool. Sub-packages:
  - `decompile/` — `Decompiler`, `SmaliDecompiler`, `DexProfileDecoderImpl`
    (smali via ANTLR: `org/jf/smali/smaliParser.tokens` + `smaliTreeWalker.tokens`
    ship in the apk).
  - `compile/` — `Builder`, `SmaliCompiler`, `DexProfileEncoderImpl`.
  - `protect/` — the encrypt/obfuscate engine (see §4): `Protector`,
    `DexConfuser`, `DexStringFogger`, `DexArrayPayloadConfuser`, `TableConfuser`,
    `FileNameConfuser`, `ManifestConfuser`, `DirectoryConfuser`,
    `ProtectedFileWriter`, `ProtectorOptions`.
  - `refactor/` — `AutoRefactor`, `TypeNameRefactor`, `EntryRefactor`.
  - `merge/`, `cloner/`, `info/`, `smali/`.
- **Full Android bootclasspath bundled** as `frameworks/android/android-23.apk`
  … `android-36.apk` (13 files). smali decompile uses `-b $BOOTCLASSPATH` — this
  is what lets it decode apps down to API 23 without the host SDK.
- **Chaquopy (embedded CPython 3.11)** — `libpython3.11.so` + `assets/chaquopy/`
  (`app.imy` = a zip of `hbctool` .pyc, `requirements-*.imy`). The Python half is
  the **Hermes Bytecode (HBC) tool** (React Native): `hbctool` (bongtrop/hbctool,
  MIT) ported — `disasm`/`asm` of HBC versions hbc59–hbc99
  (`hbctool/hbc/hbcNN/{__init__,parser,translator,data/opcode,data/structure}.pyc`),
  `hasm.pyc` (the .hasm reader/writer: `read_all_func`/`read_func`/`write_func`
  match the format
  `Function<.*?>([0-9]+)\(([0-9]+) params, ([0-9]+) registers,\s?([0-9]+) symbols\):`
  … `EndFunction`), `util.pyc` (BitReader/BitWriter for the bytecode stream).
- **BouncyCastle** (`org.bouncycastle.*`) — RSA/keystore crypto for the
  Signature Creator/Converter (keystore → pk8 private key + x509 cert, for MT
  Manager signing).
- **ANTLR stringtemplate** (`org/antlr/stringtemplate`) — used by SmaliToRegex.
- **`libpairipcore.so`** (2,266,144 B, arm64+v7a) — the **pairip** (Javier
  Santos piracy protection) core; the native dex-protection/decrypt half.
- Analytics: PostHog (`eu/us.i.posthog.com`) — the only real network endpoints
  in the dex; the **pattern DB is NOT a fixed URL** (see §5).

## 2. The patch model — smali regex search-and-replace

The entire "remove ads / unlock VIP" surface is:
**decompile to smali → regex search-and-replace over the smali text → reassemble
→ (re)sign → install.** No LSPatch, no Frida, no runtime hook (that is the point
of the name *AdsRegex*).

- **`rs.adsregex.tools.SmaliToRegexConverterActivity`** is the meta-tool: you
  paste/select a smali snippet and it **generates the regex** that matches it
  (ANTLR stringtemplate + `ReplaceRegexGen`). This is how the named patches are
  authored. `RegexTester` validates a pattern before applying.
- The canonical example the UI teaches (in the resource strings, EN+ID+TR+…):
  boolean gate → `const/4 ([pv]\d{1,3}), 0x0`  matched and replaced with
  `const/4 \1, 0x1` (force-true). Same shape as our r2ai `flipTrue`.
- **Pre-step the UI keeps repeating:** "Remove all debug info" (Dex Editor
  Plus → Preferences) before applying the obfuscation-sensitive patches
  (developer-options, USB-debug, no-logs, unlimited-trial, hide-mock-location).
- Multi-regex batteries: `CommonRegex` is numbered "Regex 1…9+", e.g. **Regex 5
  = pairip** ("search for pairip without regex, then in current results use
  Regex 5"). `LowLevelRegex`/`MidLevelRegex`/`HighLevelRegex` = three depths of
  ad-removal.

## 3. Every patch activity (rs.adsregex.patches.* — the full list)

| Activity | What it does | technique class |
|---|---|---|
| CommonRegex | core ad/analytics/billing removal, numbered regex battery | smali regex battery |
| LowLevelRegex / MidLevelRegex / HighLevelRegex | ad removal at 3 granularities | smali regex battery |
| BillingActivity | remove in-app billing | smali regex |
| AnalyticsActivity (V2 in v10) | remove analytics/tracking | smali regex |
| NoLoggingActivity | remove logging | smali regex (needs debug-info removed) |
| **LazyUnlockPatchActivity / V2 / V3** | **unlock Premium/VIP/Pro/Gold/Subscription** | smali regex (lazy = broad, low-risk) |
| UnlimitedTrialActivity | enable unlimited trial | smali regex (debug-info removed) |
| BypassLicenseVerificationActivity | client/device-side license check | smali regex |
| PlayStoreRedirectionBypass | stop pairip's Play-Store redirect on license fail | smali regex |
| PiracyCheckBypassActivity | Javier Santos piracy checker | smali regex |
| PairipRemovalActivity | remove pairip protection (libpairipcore) | smali regex + `libpairipcore.so` + Termux `pairip.py` script (see §4) |
| RevenuecatActivity | locate Revenuecat billing hints | smali regex (hint finder) |
| RootActivity | remove root detection | smali regex |
| DisableEmulatorCheck | disable / spoof emulator check | smali regex |
| DeveloperDetectionBypass | developer-options detection | smali regex (debug-info removed) |
| USBDebuggingDetectionBypass | USB-debug detection | smali regex (debug-info removed) |
| RemoveSniffDetection | HTTP Canary / SSL Capture / Packet Capture / Lucky Patcher hardcoded package-name checks → replace literals with harmless placeholder | smali string replace |
| HideMockLocation | prevent "location mocked by 3rd party" detection | smali regex (debug-info removed) |
| CountryRestrictionBypass | country/region locks | smali regex |
| VPNDetection | VPN detection | smali regex |
| ScreenshotRestrictionPatch V1–V4 + SecuredScreenRestrictionPatch | `FLAG_SECURE` / `setSecure(true)` on SurfaceView | smali regex (4 variants + secure-screen) |
| DisableDialogsActivity / DisableToastActivity / LazyDialogToastActivity | kill custom dialogs/toasts (rate, force-update, welcome, credit) | smali regex (only non-obfuscated/non-encrypted) |
| RemAnyPermission / RemInternetPermission / RemLocationPermission | remove a permission (name → generated regex) | manifest + smali regex |
| NoPlayServices | strip Google Play Services → AOSP | smali + manifest regex |
| GoogleMapsAPIActivity | Google Maps API handling | smali regex |
| PackageInstallerFix | fix installer so app installs | smali regex |
| RootActivity | (root, above) | |

## 4. Every tool activity (rs.adsregex.tools.* — the workbench)

- **ApkeditorDecompile / ApkeditorCompile / ProtectActivity** — the REAndroid
  decompile / recompile / protect round-trip (the actual "compile" + "encrypt").
- **APK Converter** (`ApkDataMultiplex`? no — separate) — `.apks`/`.xapk`/
  `.apkm` → single `.apk` (v27+ opens from any file manager).
- **SmaliToRegexConverterActivity(+Old)** — smali → regex generator (meta).
- **RegexTester** — test a pattern against smali before applying.
- **ReplaceRegexGen** — generate a replacement regex.
- **MTHookGenerator** (v25) — generate an MT Manager **hook** (Xposed-style
  smali hook) "to remove signature without other apps".
- **GenSignActivity / SignatureConverterActivity** — Signature Creator
  (advanced options) + keystore → pk8 + x509 (BouncyCastle) for MT Manager.
- **BlutterDumper / BlutterActivity / FlutterPatcher** — Flutter: blutter
  (Dart AOT snapshot → decompiled Dart) + patch. Detect Flutter via
  `lib/arm64-v8a/libflutter.so`.
- **HBCToolActivity** — React Native Hermes bytecode disasm/asm (Chaquopy
  `hbctool`, hbc59–99).
- **Dex2C** — dex → C (decompile assist).
- **DexRepairActivity / DexFileCleanerActivity** — repair DEX header/checksum;
  clean system-dumped dex (Frida leftovers) leaving only app dex.
- **LibPatcher** (v26) — native `.so` patching via radare2: `r2 -w lib.so`,
  `wx <hex>` @ address; teaches the `add x0, x22, 0x20/0x30` register patch and
  "same-length string replace" rule.
- **CRCPatcher** — CRC patch (dex/zip integrity after edit).
- **AssemblyConverter** — ARM assembly ↔ hex (single-line input v26).
- **StringToHexActivity / BaseEncodingDecoding / BaseConverter /
  TimeConverter / ColourConverter / MorseTextActivity** — converters.
- **CheckArchitecture / CheckIP / CheckMyIP** — ABI support check, IP lookups.
- **MergeActivity** — merge (APK parts).
- **DexFileCleanerActivity** — (see above).
- **ProtectActivity** — APKEditor protect (see §4 of this note).

## 5. Encryption / decryption — the exact mechanisms

1. **REAndroid `protect` (the "Protect APK" / "Apkeditor Protect" feature).**
   NOT classical symmetric encryption — it is a **confuser/fogger** pipeline:
   `DexConfuser` (obfuscate class/method/field names), `DexStringFogger`
   (string pool fogging), `TableConfuser` (dex table obfuscation),
   `DexArrayPayloadConfuser` (payload arrays), `FileNameConfuser` +
   `ManifestConfuser` + `DirectoryConfuser` (entry-name shuffling), all driven
   by `Protector`/`ProtectorOptions` and written by `ProtectedFileWriter`.
   v30.0.1 added a **"Protect Dex" option**. Decrypt = the matching REAndroid
   decompile pass (it can read back what it wrote — same library).
2. **pairip (`libpairipcore.so`).** The classic Javier Santos piracy
   protection: the real DEX payload is **compressed/protected**, and a
   `com.pairip.application.Application` bootstrap decompresses it at runtime.
   AdsRegex's removal path (guide, EN): (1) download the pairip assets,
   (2) put `.apk`/`.apks` in the pairip script folder, (3) run
   `python3 pairip.py` in Termux, (4) **install the unsigned app** (rooted, or
   VMOS/vphonegaga) to **get the dictionary file**, (5) apply the pairip regex
   (Regex 5) → de-protect. So the "decrypt" for pairip is: run the app once to
   let the native core emit its dictionary, then smali-regex the bootstrap.
3. **Hermes HBC (React Native).** "decryption" = disassemble the Hermes
   bytecode (`.hbc`/bundle) to `.hasm` text (Chaquopy `hbctool`), patch the
   `.hasm`, reassemble. The `.hasm` function header format is
   `Function<name>(N)(P params, R registers, S symbols):` … `EndFunction`,
   with typed operand lines `; Oper[i]: String(...)` etc.
4. **Flutter (Dart AOT).** "decryption" = **blutter** (Dart snapshot
   decompiler) → readable Dart, patch, (PPTool/radare2 for the offset flip).
5. **Base64 / Base-N / time / colour / morse** — the converter tools
   (`BaseEncodingDecoding`, `BaseConverter`, `TimeConverter`, `ColourConverter`,
   `MorseTextActivity`) for hand-patching hex/strings.
6. **BouncyCastle RSA** — keystore/private-key crypto for re-signing
   (Signature Creator/Converter), not APK content encryption.

## 6. Where the pattern DB actually is (the key non-obvious fact)

- The named patches' **regex strings are NOT in the apk's DEX string pool**
  (we found 0 `const-string` in `rs.adsregex.*`; the method names are
  obfuscated to 8-char ids). The apk ships `downloading_update`,
  `MandatoryUpdateActivity`, a DataStore key `PATTERN_DP`, and PostHog only.
  → **The pattern library is downloaded at runtime** (self-update / "Mandatory
  update") and cached in DataStore; the UI then feeds those patterns into the
  SmaliToRegex/RegexTester/apply pipeline. That is why a fresh install needs
  internet once.
- Consequence for vibe `/kit`: we should **bundle a static pattern DB**
  (JSON, per-patch list of `{match, replace, needs_debug_removed,
  targets:[smali|manifest|arsc|native]}`) under `tools/vibebot/patterns/`, and
  optionally support a remote-update URL (same `PATTERN_DP` idea) — but the
  bundled DB means it works offline, which AdsRegex does not.

## 7. The patch pipeline (reproduced — this is what /kit will run)

1. **Intake**: unzip, inventory (manifest via AXML, dex list, native libs,
   flutter/HBC detection: `libflutter.so` → Flutter; `.hbc`/RN markers → HBC;
   `libpairipcore.so` → pairip).
2. **Decompile**: REAndroid/APKEditor `d` (smali + res + manifest), bootclasspath
   from bundled `frameworks/android/android-*.apk`.
3. **Classify**: which patches apply (ads present? billing? license? flutter?
   pairip?).
4. **Pre-step**: if a chosen patch needs it, "remove all debug info" first.
5. **Patch**: apply the pattern battery (smali regex replace; manifest/arsc
   edits; for native, `r2 -w` + `wx <hex>` same-length).
6. **Reassemble**: smali → dex → apk (APKEditor `b`/`compile`).
7. **CRCPatch** integrity (CRCPatcher).
8. **Sign**: apksigner (v1/v2) with a provided or generated keystore;
   SignatureConverter exports pk8+x509 for MT Manager if the user signs there.
9. **Report**: per-pattern match count (0 is a valid outcome — the ApkToolPatcher
   / AdsRegex convention), what changed, install note.

## 8. Map to vibe / r2ai (what to build)

- **`/kit` command group on the VibeBot** (the read-only analyzer's missing
  half) should implement the §7 pipeline, **offline, with a bundled pattern DB**
  — this is strictly better than AdsRegex (which needs a runtime download).
- The **R2AI Android app** (v4.0 one-tap presets) already covers the boolean-flip
  + ad-void + date-future byte primitives; AdsRegex adds the **named smali-regex
  batteries** (LazyUnlock/VIP, UnlimitedTrial, screenshot-secure, sniff-detect,
  pairip) and the **Flutter/HBC/native** decompile routes.
- Reuse, don't rebuild: REAndroid APKEditor is a public Apache/MIT library we can
  bundle into the bot (it is already in this apk at 1.4.9). `hbctool` is MIT.
  blutter + r2 are already in the r2ai skill.
- **License note:** AdsRegex itself is proprietary (© its author, changelog
  "Initial Release May 10 2024", renamed to "Ads Regex+" in v8). We adopt the
  *technique*, not its code/patterns. REAndroid + hbctool are permissively
  licensed and safe to bundle.

## 9. Provenance

- APK bytes: MediaFire a9wb7t6cjzy2x2u (43,882,283 B) — read-only, downloaded
  2026-10-29 to `/opt/data/cache/scratch/adsregex.apk`.
- DEX/manifest: androguard 4.1.4 (`DEX`, `APK`) — 11,686 classes, 41
  `rs.adsregex/patches|tools` targets enumerated; 0 const-string in app classes
  (patterns are runtime-downloaded, §6).
- `assets/chaquopy/app.imy` (418,125 B) = zip of `hbctool` .pyc (Python 3.11);
  decompiled-by-constants (magic `a70d0d0a`); `metadata.pyc` → hbctool 0.1.5,
  MIT, bongtrop/ErbaZZ, github.com/bongtrop/hbctool.
- REAndroid: `assets/apkeditor.properties` = `repo=…/REAndroid/APKEditor`; 52
  `com.reandroid.apkeditor.*` classes incl. full `protect/` package.
- `libpairipcore.so` (2,266,144 B) — pairip core.
- `tas33n/AdsRegex` GitHub = landing site only (no source); real engine is the
  apk.
