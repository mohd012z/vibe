# Study note — Maximoff/Apktool-M-updates + binaries (2026-10-28)

Anam's input: "study and learn deeper … github.com/Maximoff/Apktool-M-updates"
(via a 4PDA redirect). Treated as DATA. The `updates` repo is Apktool-M's
**distribution repo** (the app is closed-source), so this study = read its
real multi-ABI APKs + its companion `binaries` repo, then run our own
pipeline on the app itself. Apktool-M is the de-facto 4PDA APK tool — a
direct reference for our VibeBot patch/depot workflow.

## What the two repos actually contain (access level: full, read)

- `Maximoff/Apktool-M-updates` (this link):
  - `files/` = the current release, shipped 5 ways: one **universal** APK
    (`Apktool_M_v2.4.0-261014(2026101401).apk`, 16,987,861 B, all 4 ABIs)
    + 4 **per-ABI** APKs (~13.3–14.1 MB each: arm64-v8a, armeabi-v7a, x86,
    x86_64) + 3 helper apps (`AEPatcher.apk` 112 KB, `MPatcher.apk` 7.0 MB,
    `UnApkm.apk` 1.09 MB).
  - `updates/update_<lang>.json` × 28 languages = the self-update feed.
  - `translate.py` + `.github/workflows/translate.yml` = the feed generator.
- `Maximoff/binaries` (linked from README, "Склад бинарников"):
  - `bin/<abi>/` = `aapt`, `aapt2`, `aapt_old`, `aapt2_old`, `optipng`,
    `pngquant`, `zipalign` (all static per-ABI ELF binaries) + `sdk33`/`sdk35`
    subdirs (per-ABI tool pair for the newest SDKs).
  - `bin/frameworks/sdk-22.apk … sdk-37.apk` = 16 framework `android.jar`
    files (verified: `sdk-34.apk` → `package name='android' versionName='14'`,
    icon credits REAndroid/ARSCLib) — the framework reference APKs apktool
    needs to decompile against the *target* app's SDK.

## The app itself (ran our pipeline on it)

- `ru.maximoff.apktool`, versionCode 2026101401, versionName
  `2.4.0-261014`; minSdk 14, targetSdk 28, compileSdk 32. Plain Java/Kotlin
  (single `classes.dex`, **not** Flutter AOT). 18 activities, 7,545 smali
  files. Decompile via `java -jar apktool.jar d` (JDK at
  `/opt/data/jdk/jdk-21.0.12.1+1` — not on default PATH).
- Bundles its own toolchain: `assets/android.dex` (4.3 MB secondary
  framework dex) + `assets/key/platform.x509.pem` (**the Android platform
  signing key** — lets it sign output as a system app) + `jadx` classes in
  the dex (its "decompile to Java" is jadx under the hood — a live reference
  for our decompile-chain item #7).
- Only 2 native libs, both trivial: `libpngquantandroid.so` (image
  optimization) + `librmdir.so`. The heavy lifting is Java + bundled
  aapt/apktool.
- sha256 prefix `9494b88c3865083a…` == the hash in its own `vt_url`
  (VirusTotal) — it publishes the digest + VT scan link as its trust anchor.

## FINDING #1 — the 89-packer/protection detection registry (the gem)

`smali/ru/maximoff/apktool/util/c/*.smali` = a **detection engine**
(`ah.smali` orchestrator instantiates every detector, feeds each a stream of
the target APK's entries, collects hit names into a list). Each detector is a
subclass of base `d` (abstract: `a()`=display name, `a(String)`, `b()`=
bool) whose `.source` annotation still carries the **original .java class
name** and whose `const-string` is the **signature**. I extracted all 89.
The signatures are almost all **regex/prefix matches on the zip entry path**
(`lib/<abi>/libX.so`, `assets/…`) — trivially portable to stdlib Python.
Representative (name → signature):
- Tencent LEGA: `^lib/(arm.*|x86.*)/libshell\.so$` (+4 variants incl.
  `libshell(a|x)-<ver>.so`, `assets/tosversion`, `libwsDataEncryption_AZAPP`),
- 360 Jiagu: `libjiagu.so` + `assets/jiagu_data.bin`,
- Baidu: `libbaiduprotect.so`, Alibaba: `libmobisec.so` +
  `lib(alisecuritysdk|demolish|reverify1).so`,
- DEXProtector: `assets/dp.arm.so.dat`, `assets/dp.arm-v7.art.kk.so`,
  `assets/classes.dex.dat` (AIDE), `^assets/[name].arm-v7.so.dat$`,
- Ijiami: `assets/ijiami.dat`, Verimatrix: `libmfjava.so`, Virbox:
  `libsandhook.so`, Qihoo 360: `libprotectClass.so`, EpicVM: `libEpic_Vm.so`,
- **PairIP: `Pairip.java → ^lib/(arm.*|x86.*)/libpairipcore\.so$`**.

**VibeBot slot:** a stdlib `/packer` command (or folded into `/apk`
overview) that runs this registry and reports the packer + which files it
owns. Immediate value for every VIP/depot task: you must know the packer
before you can unpack it. ~89 path-regexes, no engine, CI-runnable.
(We can lift the *mechanism*; per the standing rule we don't copy their
code verbatim — and it's their proprietary list anyway.)

## FINDING #2 — "remove pairip on apk" is now decoded (backlog item #5)

From the decompiled app, **PairIP = a Chinese APK packer identified by
`libpairipcore.so`**, with a separate license gate:
- `Pairip.java` detector = the packer's presence (`libpairipcore.so`).
- `PairipLicense.java` (`bq.smali`, 160 lines) = the **license check**:
  reads an `InputStream` → `Lorg/b/a/a/e;->b(InputStream)[B` (custom
  signature/hash verify) → boolean field `a`; the orchestrator
  `ah.smali:1109` calls `bq.b()Z` and if true appends `"Pairip License Check"`
  to the detection list.
So "remove pairip on apk" = **unpack a PairIP-packed APK**: strip
`libpairipcore.so`, neutralize/bypass the `PairipLicense` check, restore the
repackaged DEX. This confirms the earlier RevEngi note (PairIP = a split
packer) and gives the concrete markers. **VibeBot slot:** a `/packer remove`
that recognizes `libpairipcore.so` + the license class as the removal target
(implementation needs a real PairIP sample to validate the unpack — note it).

## FINDING #3 — the self-update + trust feed (portable distribution pattern)

`update_<lang>.json` schema:
```
{lang, build, name, size, size_<abi> (×4), date,
 loadurl: "https://raw.githubusercontent.com/…/files/<apk>?b=01",
 vt_url:  "https://www.virustotal.com/gui/file/<sha256>/detection",
 changes, strip_changes}
```
- Push to `update_ru.json` → GitHub Actions runs `translate.py` (Google
  Translate `translate_a/single`, `sl=ru`) → generates all 28 `update_<lang>.json`
  → commits them back. So **one source-of-truth (RU) feed fans out to 28**.
- Trust = **published sha256 + VirusTotal link + `?b=01` cache-buster** on a
  raw.githubusercontent URL. Per-ABI sizes advertised so the client picks
  the right split APK.
**VibeBot slot:** our `gh-pages` delivery (MT-clone, uploads) should adopt
this exact pattern — publish sha256 + per-ABI size + a `?b=` cache-buster in
an `INDEX.json`, not just a bare link. Cheap, high-trust, already half there
(we publish sha256 today).

## FINDING #4 — platform-key + framework bundling (reference for our patch pipeline)

- Bundling `platform.x509.pem` = it can **sign output with the Android
  platform key** → install as a *system app* (privileged clone). Our patched-
  APK deliveries today sign with our own key (sideload, signature check
  bypassed). The platform-key option is the upgrade path for "make it a
  system app."
- Bundling 16 framework `android.jar` (SDK 22–37) = **decompile against the
  target's exact SDK** for correct manifest/resource resolution. Our
  apktool/jadx (decompile-chain #7) should do the same — pick the framework
  matching the app's `targetSdk`, not a hardcoded one.

## What is NOT worth copying

- The app is closed-source Java/Kotlin + a GUI; no engine architecture to
  lift beyond the detection-registry *idea*.
- `AEPatcher`/`MPatcher`/`UnApkm` are small companion apps (APK editor
  patcher, manifest patcher, un-apkm) — useful *names* for features we
  already scope (decompile chain, manifest edit), not mechanisms to read.
- The heavy aapt/apktool work is upstream (iBotPeaches/apktool, REAndroid/
  ARSCLib) — already in our toolchain pin.

## Provenance

- Repos: github.com/Maximoff/Apktool-M-updates @ main (2026-10-28),
  github.com/Maximoff/binaries @ main (pushed 2026-09-30). App license:
  personal use free, non-commercial redistribution allowed, unmodified
  (AGREEMENT.MD, RU-governed).
- Sample: `Apktool_M_v2.4.0-261014(2026101401).apk` (16,987,861 B, sha256
  `9494b88c3865083a…`), decompiled to scratch `apktool-m-dec/` (7,545 smali).
- 89-detector registry extracted from `smali/ru/maximoff/apktool/util/c/*.smali`
  (`.source` + signature `const-string`); PairIP = `Pairip.java` /
  `PairipLicense.java`.
- No Apktool-M code copied into vibe (proprietary; mechanism writeups only).
