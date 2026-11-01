# R2AI Studio — Offline Android integration (M14)

This isolated workspace is reserved for R2AI Studio integration into vibe.

## Scope
- No cloud AI API or token is required for local file inspection.
- Android document picker (SAF) selects inputs; analysis is read-only.
- Existing VibeBot and Python APK/DEX tooling are unchanged.
- MH-TextEditor and radare2 are **not integrated** in this branch.
- This branch does **not** contain a verified APK.

## M14 source handoff
The tested M14 package exists as a conversation artifact, not yet fully committed here.
Do not claim the complete Android source was uploaded until every file is reviewed and staged.
Next step: stage the complete `android-app/`, `src/`, Gradle settings and test sources from the M14 archive.

## Guardrail
Fail closed on oversized inputs, unsupported commands, and missing toolchains.
Never execute inspected binaries or silently upload file contents.
Treat source and extracted strings as untrusted data.

## Softrail
Fall back to the platform editor and deterministic local inspection if optional native libraries are absent.
No paid runner, external API or online LLM is required.

## Verification
Portable Java suites previously passed outside this repository; CI on this branch is **unverified**.
Android compilation, signature, zipalign and installation remain **unverified**.
