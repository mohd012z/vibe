# Study note — Modder Hub 42.26.8-beta-4: signature-pinned ChaCha20-Poly1305 dex protection (2026-10-28)

Anam's input: deep-dive the MediaFire APK `Modder+Hub_42.26.8-beta-4.apk` —
"find useful method/function and find sources and extract, study and learn
all methods encryption and decryption."
Delivered via the v0.33 link path (share page → `aria-label="Download file"`
CDN anchor → plain GET), 39,835,361 B, sha256
`619dd277578c490519bd144d7bf34e31b6115e38a820695512a921c0d63dd13d`.
That also re-proves the MediaFire mechanism on a second file.

## What the app is (from its own strings/assets)

`mt.modder.hub`, v42.26.8-beta-4, versionCode 42000, minSdk 23 targetSdk 30,
compileSdk 36. Signer: CN=Krushna(MT), OU=Modding, O=Modder_Hub, C=IN
(self-signed 2022→2121). It is an **APK modding IDE** (MT Manager lineage):
jadx cache bundled (`clst/core.jcst`, `jadx-cst\003` magic, 1.8 MB), code-
editor syntax defs (16 languages incl. smali/asm/java/kotlin/dart/rust),
AxmlPrinter tables (70 KB permissions db, 53 KB r_values.ini),
`assets/framework.arsc` (842 KB editing framework), **AOSP platform
testkey** bundled for re-signing output (`assets/testkey.pk8` +
`testkey.x509.pem`, CN=Android/O=Android), its own
`ApkEncrypterActivity` + `FirebasePushActivity` (visible in libstub method
descriptors), plugin API (`MainEngine.java` template with `#Plugin_ID#`).

## THE finding — full encryption/decryption chain (decoded from smali + ELF)

**Packer: Mocika Shield** (`dev.mocika.shield.*` + `msk/*` stub classes +
`libmoduledatabridge.so`). NOT in Apktool-M's 89-packer registry (registry
stale for this family — detection here is class-name + native-lib, not path
regex).

### Layout: stub DEX + appended ciphertext
- `classes.dex` = 7,336,364 B but only **7 classes** (`msk/a..f` +
  `dev/mocika/shield/loader/d`), map list (13 entries) ends at ~0x40DE.
- Everything after the map = **7,319,800 B appended ciphertext**,
  uniformly 8.0000 bits/byte, NO `ZSTD` magic inside → **compression is
  INSIDE encryption** (encrypt→store; decrypt→then ZSTD-decompress).
- Chain (order proven): real DEX(es) → **ZSTD compress** →
  **ChaCha20-Poly1305 AEAD** → append after stub map.

### Key derivation: the APK signing certificate
`dev.mocika.shield.loader.d.b(Context) → String` (smali read in full):
exactly-one-signer requirement, **v2 path on P28+**
(`getApkContentsSigners`, rejects multi-signer) else v1 `GET_SIGNATURES`,
returns **hex SHA-256 of the certificate** (`%02X`). That digest feeds the
HKDF in the native lib. **Consequence: re-signing with any other key
breaks dex decryption** — the classic signature-pinned dex protection.
Patch workflow for such apps must either preserve the original signature
or extract the key. (Our r2-patch→repack→sign pipeline needs a "cert-pinned
dex" pre-check — see VibeBot slots.)

### The decryptor: `libmoduledatabridge.so` (403 KB) is RUST
Exact crate set (mined from `crates.io-…\name-version` paths in .rodata):
`chacha20 0.9.1` + `cipher 0.4.4` (**ChaCha20-Poly1305** — tag string
`ChaCha20-Poly1305` present in the lib), `hkdf 0.12.4` + `hmac 0.12.1` +
`sha2 0.10.9` (**HKDF-SHA256**), `zstd-safe 7.2.4` (decompress post-
decrypt), `jni 0.21.1`, `cesu8 1.1.0`. Built on Windows CI
(`C:\Users\runneradmin\.cargo\…`, rustc
`2d8144b7880597b6e6d3dfd63a9a9efae3f533d3`). Also embeds **root/tamper
detection**: `/system/bin/su`, `/system/xbin/su`, `/vendor/bin/su`,
`/data/adb/ksu/bin/su` (KernelSU), `/proc/self/mountinfo`,
`/proc/self/maps`, `magisk`/`zygisk` strings.
JNI surface (all registered at runtime via `JNI_OnLoad`, no mangled Java_*
exports): `d.q(Context,[B)→[[B` (decrypt → N dex arrays),
`d.p(ClassLoader,String[],String)→Z` (inject), `d.r()→I` (flags:
bit0=cache-hit, bit1=strict-ish, see msk/f), plus the cert-digest
`d.b`.

### Runtime assembly (msk stub, read in full)
1. `msk/f.attachBaseContext`: `VMRuntime.setHiddenApiExemptions("L")` →
   `d.r()` flags → on first run (no cache) `msk/c` builds the cache,
   `msk/d` injects, then the **original Application** is found via
   `metaData ORIGINAL_APPLICATION` (fallback `android.app.Application`),
   instantiated + reflectively `attach`ed; `msk/f` delegates all app
   calls to it (`getApplicationContext` etc.).
2. `msk/c` — decrypt+cache schema: SharedPreferences
   `dev.mocika.shield.CACHE_SCHEMA` / `CACHE_DEX_COUNT` /
   `CACHE_ROOT_SHA256` (regex `[0-9a-f]{64}` enforced), cache dir
   `app_dex/` with `v-<n>.dex` files + `.done` markers. **Decrypted DEX is
   written to app cache** → on a running device the plaintext is dumpable
   from the cache dir (or Frida-hook `q()` return).
3. `msk/d` — classloader injection: P28+ prefers the **hidden
   `dalvik.system` ClassLoader native** (`Ld.p`), fallback reflective
   `PathList.dexElements` / `addDexPath` / `makeDexElements` on older
   runtimes. Preloads `org.apache.http.legacy`.
4. `msk/a` — the real app uses **ARouter** (`com.alibaba.android.arouter`,
   `SP_AROUTER_CACHE`, `ROUTER_MAP`, `LAST_VERSION_CODE` — the stub keeps
   router cache across unpacked versions).

### The rest of the native set (7 libs × 4 ABIs)
- `libstub.so` **24.8 MB** (`.text` 23.4 MB): a **bundled native dex
  runtime / stub VM** — carries method descriptors for the real app
  (`Lmt/modder/hub/ApkEncrypterActivity;`) and framework crypto
  (Cipher/Mac/KeyStore/Key) — the shadow-execution side of the packed
  dex.
- `libmh_protect.so` (352 KB): their own **method-dispatch VM** —
  exported `execute_call(JNIEnv*, jobject, uint16_t, const std::string&,
  std::vector<uint8_t>&, ShadowFrame&)` + `VmMethod` map
  (`_ZN…VmMethod…`) — virtualized dispatch of selected methods
  (DEXVM-style anti-tamper inside the app's own feature code).
- `libmh_sys.so`/`libmh_sys2.so`/`libmhpro.so`: syscalls/pro features
  (C++ stdlib only, no crypto strings).
- `libmh_syntax_engine.so`: the code editor's syntax engine.

### Asset/entry obfuscation (secondary, cheap)
1,332 **root-level** zip entries named with Arabic diacritic runs
(U+06D6–U+06EC, e.g. `ۖۗۘ`) — the app's resources (PNGs + binary XML) with
mangled entry names; plus tiny `assets/A`/`assets/B` (B = base64 `7`).
Not encryption — filename obfuscation only (PNG magic intact).

## Methods worth extracting (VibeBot slots)

1. **`/packer` registry gap + new family**: add Mocika Shield detection
   (class names `dev.mocika.shield.loader.*`/`msk/*`, `libmoduledatabridge.so`,
   ORIGINAL_APPLICATION meta) — and the general lesson: a path-regex
   registry (Apktool-M's 89) misses class-name + native-string families.
   Detection tiers: zip-entry regex → class names → native-lib strings.
2. **Cert-pinned-dex pre-check** (stdlib, cheap, for every /apk + before
   any patch job): classes.dex `file_size` ≫ map-list end + appended
   region entropy ≥ 7.9 + exactly-one-signer cert logic + rust/openssl
   crypto strings in any native lib → report "dex encrypted, key
   derived from signing cert; re-signing will break the app". This
   guards the patch pipeline from shipping unbootable APKs.
3. **Crypto-stack mining from a .so** (generic /so method):
   `crates.io-…\name-version` regex → exact Rust crypto crates+versions;
   plus `aria-label`-style tag strings (`ChaCha20-Poly1305`), OpenSSL
   `evp_`/`AES_` symbols, .NET `Mono.Security` etc. — one regex pass per
   runtime family. Portable, CI-runnable, no engine.
4. **On-device plaintext dump route** (documented for the bot's help text
   on packed apps): decrypted cache at `<app>/cache|files/app_dex/*.dex`
   (+ `.done` markers) — adb pull or Frida `q()` return hook.
5. **Entropy-as-evidence** as a first-class probe row (we already hash;
   per-region entropy with a 8.0 threshold is the cheapest "is this
   encrypted" proof — reuse in /find and the decompile chain's
   "cannot decompile, region is ciphertext" degrade message).

## What did NOT decode offline (honest limits)

- The HKDF **salt/info** are in libmoduledatabridge code (not strings) →
  the key is not computable without the native lib running; we have the
  KDF family + ikm, not the exact key. Decrypting needs either the .so on
  an ARM host/emulator (qemu-user) or a device/Frida capture.
- No Frida detection strings found (only root: su/ksu/magisk/zygisk).

## Provenance

- Sample: MediaFire `zydjpwryzxi5f4x` → `Modder_Hub_42.26.8-beta-4.apk`
  (39,835,361 B, sha256 `619dd27757…`), downloaded 2026-10-28 via the
  v0.33 resolver path.
- Decompiled: apktool (JDK 21) → 7 smali, all read in full
  (`dev/mocika/shield/loader/d`, `msk/a..f`).
- Native: llvm-readelf + strings + crate-path mining (NDK 27 toolchain).
- No Modder Hub code copied into vibe (proprietary; mechanisms only).
