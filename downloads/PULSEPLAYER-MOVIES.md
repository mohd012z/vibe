# Pulse Player 4.0.0 — Movies / Short Drama (debug build, d18f411)

- File: PulsePlayer-4.0.0-movies-shortdrama-d18f411.apk (7.2 MB, arm64 debug)
- Package: com.pulseplayer.app — versionCode 4, versionName 4.0.0
- Branch: feat/short-drama-novel-hub @ d18f411 (includes merged PR #30 + PR #31)
- Built locally 2026-10-27 (gradle 8.13 + JDK 21): verify_source PASS, 46 unit tests, 0 failures
- Debug-signed — uninstall any other com.pulseplayer.app build first (signature differs)

## What's in this build
- PULSE CINEMA landing (Movies / ShortTV / Ratings) + Internet Archive browser (WebView)
- LocalVideo player: choose a video file OR paste an authorized HTTPS URL
  (.mp4 / .m3u8 / .mpd) — plays in a separate ExoPlayer, music queue preserved
- StoryHub: Short Drama episode player (VideoView) + Novel TXT reader
- Provider browser: YouTube / YT Music / JOOX / Spotify (WebView, tracker filter)

## Rotation fixes (this branch, verified in code + build)
- PR #30: LocalVideoActivity movie player survives portrait→landscape rotation
  (configChanges + position save/restore)
- PR #31: StoryHubActivity Short Drama player + ArchiveBrowserActivity WebView
  survive rotation (configChanges + state save/restore)

## SHA-256
6d1bd6b137a950b6b91ad4f5bcac9408df4c0866514db34bba38440de3927f66
