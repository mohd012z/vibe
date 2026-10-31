# Build verification status

Source committed; **no successful Android build or APK has been verified**.

The manually triggered GitHub workflow `.github/workflows/r2ai-studio-verify.yml` uses JDK 17, Gradle 8.9, SDK 35, then runs `testDebugUnitTest` and `assembleDebug`. It does **not** run on push or PR and must not be manually dispatched without confirming free runner availability. It cannot establish actual on-device installability; device installation and runtime tests are separate gates.

## Known concerns to check first
- Confirm AGP 8.7.3 + Gradle 8.9 + Kotlin 2.3.0 and LiteRT-LM 0.16.1 resolve together.
- `MainActivity` is a prototype shell, not the completed settings screen.
- `LiteRtLmProvider` should own Engine and Conversation on one serial executor, retain conversation across prompts, and use streaming and safe cancellation.
- Model import currently uses a fixed 4 GiB cap; needs available-space preflight and file integrity checks.
- The APK inspector and editor are not yet wired into the Android activity.
- No automatic download, paid APIs, or cloud model inference.
- Verify APK signature, zip alignment and installation on a real Android device after build.

Official API reference: https://developers.google.com/edge/litert-lm/android
