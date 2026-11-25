# Suno DL — our own Suno downloader (token-reuse blueprint)

- File: SunoDL-v1.apk (54 KB, pure Java + framework APIs — no SDK, no OkHttp, no cert pinning)
- Package: com.aliph.sunodl, versionCode 1 / 1.0.0, minSdk 26 / targetSdk 34
- v2+v3 signed (CN=Suno DL, O=Aliph, C=MY)
- sha256: 491ea83bbea0001512add0b2ca9ab7e873459e50817f4cb27bab34192bc563ee
- Direct: https://mohd012z.github.io/vibe/downloads/SunoDL-v1.apk
- Built 2026-11-25 (Aliph)

## How it works
1. Paste the browser Cookie (DevTools -> any suno.com request -> Request Headers -> Cookie) into TOKEN -> SAVE -> VERIFY.
   The app keeps the raw Cookie AND extracts the __client refresh JWT; it mints a fresh
   3600 s Bearer on demand via auth.suno.com (/v1/client -> POST /v1/client/sessions/{sid}/tokens),
   re-minting ~60 s before expiry. (Same two-tier Clerk model as the official app.)
2. LOOKUP: paste a https://suno.com/song/<uuid> url (or bare uuid) -> FETCH -> songs list
   (MP3 / COVER / ID per song). Also accepts shared links (intent-filter).
3. LIBRARY: pulls your feed (POST /a/api/feed/v3) -> same list.
4. CREATE: style (+optional lyrics/title/model, instrumental toggle) -> GENERATE
   (POST /a/api/generate/v2-web/, costs credits) -> polls get_songs_by_ids until complete -> list.
5. History (last 100, persisted) with one-tap re-download. Files ->
   /sdcard/Android/data/com.aliph.sunodl/files/Music/{audio,covers}/.

## API (capture-backed, live-verified 2026-11-25)
- Base: https://suno.com/a/api (401 unauth — the live API root; api.suno.com/a/api 404s)
- GET /a/api/clips/get_songs_by_ids?ids=<uuid> -> {result:{clips:[...]}}
- POST /a/api/feed/v3 (cursor) -> library feed
- POST /a/api/generate/v2-web/ (task/mv/gpt_description_prompt/metadata{prompt,tags,lyrics,title,instrumental})
- Auth = Bearer (minted) + Cookie; media (audiopipe/CloudFront/S3) usually public.
- Clip media: audio_url (legacy mp3) or media_urls[] ranked mp3 > m4a > webm; "/api/forbidden"
  sentinel filtered out (means still-processing / not-authorized).

## Known limits
- Token must come from a logged-in browser (Clerk login is social/OTP/hCaptcha — not headless-able).
- Exact generate response keys are runtime data; clip-id parse handles {clips:[{id}]} / {id}.
- WAV download needs the Pro-authorized /gen/{id}/convert_wav route (not wired yet).
