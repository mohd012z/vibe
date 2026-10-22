# R2AI for Android — on-device radare2 + LLM decompiler (v1.5)

- File: `r2ai-android-v1.5-aarch64.apk` (70 MB, aarch64 arm64 only)
- Package: `com.r2ai.app`, signed with Android debug key (install: allow "Install unknown apps")
- SHA-256: `916f782aff50b61d3d04f6252a90f2f5d6040f6e4d03ccb39c656060e155be2d`
- Built: 2026-10-22 from pancake's R2AI (HackBCN'25) stack
- v1.5 (versionCode 6): method list via `icj` (dex JSON, ~5s, no full -A) — fixes 'Analyzed in 53s: 0 functions' on multi-DEX apps. Decompile/Raw now work straight from icj method addresses.
- v1.4 (versionCode 5): fixes EACCES 'Permission denied' running r2blob — executables now ship in lib/arm64-v8a/ (extracted to nativeLibraryDir, exec-allowed); share data stays in filesDir via R2_PREFIX. Also: setup-latch so early Open APK waits for extraction.
- v1.3 (versionCode 4): fixes CalledFromWrongThreadException on load (dex button updated off main thread) — reported from device
- SHA-256 (v1.5): `2fe135789c282157aee70c20e7c5cc18e09e7bb20d8d62556cca7452f5ed4a5f`
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

## Caveats
- arm64 (aarch64) devices only; min API 26 (Android 8.0+).
- First launch extracts the r2 runtime (~68 MB) — takes a few seconds.
- Method list comes from `icj` (fast, per-dex) — switch dexes with the `dex 1/N` button.
  Big lists (50k+ methods on some apps) take a few seconds to build on-device.
- Debug-signed; INTERNET permission only (plus normal read of the file you pick).
- Not runtime-tested on a physical device yet — report any crash and I'll patch a v1.2.
