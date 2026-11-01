# LiteRT-LM non-GGUF AI integration (M15)

Status: **source staging, not an Android build**. This module targets LiteRT-LM and a compatible `.litertlm` model. It never assumes a GGUF model or a cloud API.

## Provider contract
`LocalAiProvider` defines load/generate/unload, keeping model selection and errors separate from Vibe's analysis tools. `LiteRtLmProvider.kt` uses the documented Kotlin Engine/Conversation APIs and is not compiled until the Android Gradle module and dependency are staged.

## Android setup UX
- On AI Chat tap, if no model is configured, show a popup: **Import model / Learn more / Continue without AI**.
- Import via Android Storage Access Framework; copy the selected file to app-private storage with a bounded streaming copy, a size/free-space check, and a user-visible progress indicator. Do not assume a SAF URI is a filesystem path.
- Display model source and license, require explicit user approval for downloads, and validate a trusted checksum if supplied by the model publisher.
- Initialize the model on a background dispatcher. Keep read-only deterministic analysis available when model loading fails.
- Keep analysis evidence separate from generated model explanations. Never execute LLM-proposed commands automatically.

## Build compatibility
Official docs: https://github.com/google-ai-edge/LiteRT-LM/blob/main/docs/api/kotlin/getting_started.md

As documented in October 2026, `litertlm-android` versions 0.17–0.18.1 contain Kotlin 2.4 metadata; use a compatible Kotlin compiler (2.3+ per upstream notes) or a compatible older runtime version. Verify the chosen version resolves and compiles before enabling the feature.

**Missing:** Android module, pinned Gradle dependency, app model importer, UI integration, actual inference and APK tests.
