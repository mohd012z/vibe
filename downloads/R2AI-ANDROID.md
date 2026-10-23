# R2AI for Android — on-device radare2 + LLM decompiler (v1.9)

- File: `r2ai-android-v1.9-aarch64.apk` (70 MB, aarch64 arm64 only)
- Package: `com.r2ai.app`, signed with Android debug key (install: allow "Install unknown apps")
- SHA-256: `916f782aff50b61d3d04f6252a90f2f5d6040f6e4d03ccb39c656060e155be2d`
- Built: 2026-10-22 from pancake's R2AI (HackBCN'25) stack
- v1.9 (versionCode 10): **SCAN ALL** one-shot (Ads-Regex style) across 7 categories — EXPIRY / VIP-Premium / ADS / ANALYTICS / SSL-PIN / SIGNATURE / LINKS — grouped output with process log + per-hit locations (dex @ vaddr / lib native). New **Expiry** (expired/notAfter/validUntil/deadline/timestamp…) + **Analytics** (firebase/sentry/posthog/tracking/metric…) + **Signature** (apksign/signingInfo/integrity/tamper/debuggable…) categories. **r2 CONSOLE**: FILE button opens any file (dex/lib/so/whatever) as r2 target, type any r2 command (iI / is ~ http / s 0xADDR; af; pdc / aaa; axt 0x…) → R2 runs it on-device and shows output.
- v1.8 (versionCode 9): **process + locations** — every scan now logs the full process (which dex parsed, string counts, timing, libs scanned) and each hit shows its LOCATION (`classes2.dex @ 0x4ae71c` or `libfoo.so (native)`). **ALL DEX** toggle (on by default: scan all dex + all arm64 lib/*.so; off = current dex only). **XREF** toggle (on-demand, slow): r2 `aaa` + batched `axt` maps top strings -> the FUNCTIONS that reference them (verified: 'No license URL' -> const-string in license-check method).
- v1.7 (versionCode 8): **SSL-Pin** scan (TDOHEX obfuscation-proof pin markers: X509Certificate/SSLPeerUnverifiedException/CertificatePinner/TrustManager…) + **grep -E** user-regex box over all dex + Patch-plan prompt upgraded with smali flips, TDOHEX invariant method, native lib hex patch (radare2 wx), apktool/apksigner re-sign steps.
- v1.6 (versionCode 7): modding workbench — **Links / VIP-Premium / Ads / Regex-HEX** offline string scans (all dex), **Patch plan (AI)** (concrete smali/hex patch + recompile & re-sign steps), **multi-APK import** (+Import, APK 1/N switcher), **Copy** (clipboard).
- v1.5 (versionCode 6): method list via `icj` (dex JSON, ~5s, no full -A) — fixes 'Analyzed in 53s: 0 functions' on multi-DEX apps. Decompile/Raw now work straight from icj method addresses.
- v1.4 (versionCode 5): fixes EACCES 'Permission denied' running r2blob — executables now ship in lib/arm64-v8a/ (extracted to nativeLibraryDir, exec-allowed); share data stays in filesDir via R2_PREFIX. Also: setup-latch so early Open APK waits for extraction.
- v1.3 (versionCode 4): fixes CalledFromWrongThreadException on load (dex button updated off main thread) — reported from device
- SHA-256 (v1.9): `2fe135789c282157aee70c20e7c5cc18e09e7bb20d8d62556cca7452f5ed4a5f`
- v1.2 adds: **Raw (off)** — offline pdc pseudocode, zero network; **multi-DEX picker** (dex 1/5 button) for big multi-dex apps

## What it is
Real **radare2 6.2.4** (official Android build) running *on your phone*, wired to an LLM:
pick any APK (or raw `.dex`) with the Open APK button → full on-device analysis →
decompile / explain / vuln-check / agentic auto-analysis of any method, results from the LLM.

- Reversing (dex parse, `-A` analysis, `pdc` pseudocode) happens **locally** via native
  `r2blob` + 23 r2 libs bundled in the APK (~68 MB assets, extracted on first launch).
- The LLM gets the pseudocode and returns C code / explanations / findings.
- **Providers:** Minda (team key preloaded — no setup) **or** ChatGPT/OpenAI (tap
  `Key ⚙`, paste your `sk-...` key; stored on-device only).

## Buttons
| Button | Does |
|---|---|
| Open APK | SAF picker → extracts classes.dex → runs full `-A` (1–3 min on big apps) |
| method list + ⟳ | every function found (address + name); ⟳ re-runs analysis |
| Decompile | pdc → clean C via the LLM (decai-style) |
| Explain | plain-English walkthrough of the method |
| Vulns | buffer overflow / UAF / integer / format-string / TOCTOU findings + exploit snippets |
| Auto | agentic loop: LLM drives `r2cmd` tool calls (iI/is/pd/px/pdc…) up to 8 steps, then FINAL answer |
| Raw (off) | on-device pdc pseudocode, zero network |
| Links / VIP-Premium / Ads / Regex-HEX | offline string scans across ALL dex (URLs, premium/license strings, ad SDKs, hex/base64/regex) |
| Patch plan (AI) | concrete patch: what smali/hex to flip, where, alternatives (LSPatch/Xposed), + recompile & re-sign steps |
| + Import / APK 1/N | load multiple APKs and switch between them |
| SSL-Pin | offline scan for SSL-pinning markers (TDOHEX invariants) — pin-check methods to clear to return-void |
| grep -E box + GREP | type any regex (case-insensitive) → match across ALL dex strings, offline |
| ALL DEX / XREF toggles | scope scanner to all dex+libs vs current dex; XREF maps strings → referencing functions (r2 aaa+axt) |
| Process log | every scan prints the steps taken + per-hit locations (dex @ vaddr / lib) |
| SCAN ALL | one-shot across 7 categories (Ads-Regex-Official style) — expiry, premium, ads, analytics, ssl-pin, signature, links |
| Expiry / Analytics / Signature | new scan categories (trial/date checks, tracking SDKs, tamper/signature checks) |
| FILE + r2 console | open any file (dex/lib/so) as r2 target, run arbitrary r2 commands on-device |
| Copy | copy the output pane to clipboard |

## Caveats
- arm64 (aarch64) devices only; min API 26 (Android 8.0+).
- First launch extracts the r2 runtime (~68 MB) — takes a few seconds.
- Method list comes from `icj` (fast, per-dex) — switch dexes with the `dex 1/N` button.
  Big lists (50k+ methods on some apps) take a few seconds to build on-device.
- Debug-signed; INTERNET permission only (plus normal read of the file you pick).
- Not runtime-tested on a physical device yet — report any crash and I'll patch a v1.2.
