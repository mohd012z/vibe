# APK release blockers — 2026-11-01

This file records confirmed source/infrastructure risks; it is **not** a successful build report.

## Build infrastructure
- Android SDK and Gradle were absent from the available execution container.
- External Gradle distribution download failed due to DNS/network restrictions.
- The GitHub connector exposes workflow logs/artifacts and retry operations, but no workflow_dispatch operation.
- The manual-only workflow is on a feature branch. GitHub workflow_dispatch normally requires the workflow file to exist on the repository's default branch before the UI/API can dispatch it. Since main must remain unchanged, do not assume the workflow can be triggered from the Actions UI.
- Do not enable billing, merge the draft PR, or represent a source ZIP as an installable APK.

## Code issues to resolve before release
1. Verify Gradle 8.9, AGP 8.7.3, Kotlin 2.3.0 and LiteRT-LM 0.16.1 resolve together. Run :app:compileDebugKotlin and :app:assembleDebug.
2. Confirm LiteRT-LM Engine/Conversation APIs and return types against the resolved AAR. Source has not compiled.
3. Current import copies up to 4 GiB without checking available storage; imported file validation relies on native initialization.
4. Model switching initializes a second model while the first is still resident. This can cause Android low-memory termination.
5. UI's activity owns provider and shuts it down on an untracked background thread; configuration changes and cancellation need lifecycle tests.
6. No on-device streaming/cancellation or verified APK/DEX-to-AI bridge.
7. Release checks: unit tests, APK presence, signature, zip alignment, checksum, install, launch, real model load, repeated prompts, memory-pressure and rotation tests.

## Zero-cost phone-first execution route
If GitHub Actions dispatch cannot see the feature-only workflow, keep PR draft and use a free available Android-capable environment **only after checking its quotas**. Do not move CI to main or incur charges without user approval. Alternatively run a local Android build on an Android phone with an installed toolchain and report exact logs. There is no verified APK yet.
