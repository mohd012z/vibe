# Offline release gates

| Gate | Requirement |
|---|---|
| Source integrity | Pin upstream revisions; preserve license notices |
| Input | SAF-selected, read-only, bounded by 8 MiB for basic inspector |
| Processing | No execution of user-selected APK/DEX/ELF files |
| Output | Bounded, local, no network or API calls |
| Cancellation | Cooperative; no stale UI callback |
| Editor | Preserve unsaved work and verify save result |
| Toolchain | Actual Android SDK and Gradle compilation |
| APK | Verify signature, alignment, install and launch |
| License | Resolve MH-TextEditor conflicting license notices before distribution |

A missing native runtime or AI model is not an application failure. Display unavailable status and use the local fallback.

**No green build claims without logs and artifacts.**
