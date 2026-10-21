# Pulse Player 4.0.0 — YouTube Download + No-Ads (AI Pulse Studio base, debug build)

- File: PulsePlayer-4.0.0-yt-download-adfree.apk (60 MB, arm64 only)
- Base: **feat/ai-pulse-studio-foundation** (your current build: AI Pulse Studio + ONNX +
  Malaysia radio + cinema) with the new YouTube features layered on top
- New:
  - Main screen: **⬇ Download YT / YT Music** + **♫ Play YT — no ads** buttons
  - In-YouTube-player **Download** button now actually downloads the current
    track (was: "Not a direct media file" error) — MP3/FLAC/M4A/OPUS + cover art
  - Ad-free playback: yt-dlp resolves the raw stream, media3 plays it in-app (no YouTube UI)
- Package: com.pulseplayer.app — versionCode 4, versionName 4.0.0
- Bundled static yt-dlp aarch64 v2026.08.19 (40 MB asset)
- arm64 (64-bit) devices only — every phone since Android 11.
- **Different signing key than the full 4-ABI debug build** — if you had the old
  4.0.0 build installed, uninstall it first (signature conflict).
- SHA-256: ed29f43c0e6120f7da9e481dd4df5320b3ea07b92d8968dae1e6ccc2c014bc84
- PR: https://github.com/mohd012z/Pulse_Player/pull/28 (commit 5ae9bf7)
