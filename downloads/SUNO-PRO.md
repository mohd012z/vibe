# Suno Pro — suno.ai clone (native Android)

- File: SunoPro-v1.apk (5.3 MB, arm-independent — pure Java + framework APIs)
- Package: com.aliph.suno, versionCode 1 / 1.0.0
- minSdk 26 / targetSdk 34, v2+v3 signed (CN=Suno Pro, O=Aliph, C=MY)
- Direct: https://mohd012z.github.io/vibe/downloads/SunoPro-v1.apk
- Built 2026-11-25 (Aliph) — study build: a deep-dive clone of the suno.ai web app.

## What it is
A native Android app that rebuilds the suno.ai product experience:
- **Design system transcribed live from suno.ai** (2026-11-25): black background,
  gold `#C4A670` accent, magenta `#FD429C`, gold/magenta gradient progress,
  standalone display (web manifest values reused).
- **Real plan table**: Free / Pro $10–$96 / Premier $30–$288 / Artist $120–$1200,
  with the exact credit + download quotas and feature lists from suno.ai's
  `initialPlans` payload.
- **Real product gates reproduced**: model v4/v4.5 locked behind Pro (the site's
  `v4` usage-plan feature flag), downloads gated by plan (Free = none,
  Pro = 20/mo, Premier = 60/mo, Artist = 120/mo), 10 credits per create,
  Free = 50 credits/day with ad bonus, priority-queue copy.
- **Create flow**: Simple/Custom modes, idea + style + lyrics + title,
  instrumental toggle, model picker, staged progress (analyze → compose →
  vocals → mix → render), songs land in My stuff (persisted, deletable).
- **Persistent player bar**: play/pause, seek progress, like, download
  (writes WAV to Music/SunoPro), model badge, PRO tags.

## Honest scope
- **Audio = 6 locally synthesized demo tracks** (numpy-generated WAVs,
  deterministic per seed). No Suno recordings, no real AI generation —
  the pipeline (credits → gate → progress → My stuff → download cap) is the
  real one, the audio bed is a stand-in.
- Demo checkout: no real payment (real app is Stripe-backed via
  /api/billing/change-plan etc.).
- Not Play Store material (custom signing key, no Play Protect optimization).

## What was studied (source: live suno.ai, Nov 2025-11-25 capture)
- Next.js 16 App Router SPA (RSC streaming), PWA manifest, 80 JS chunks (~3 MB).
- Plan objects: `plan_key`/`level` 0/10/30/75, `usage_plan_features`
  (v4, cover, edit_mode, persona, studio, get_stems, max_mode, custom_models…).
- Model lineage in code: v2 → v3 → v3.5 → v4 → v4.5 (+ codenames auk, bluejay,
  crow, eagle, fenix, goose, hawk, ibis, junco).
- Audio contract: webm-opus / m4a-opus (encrypted) + mp3 (clear), delivery via
  audiopipe + CloudFront (dn3ebm5xp8ng9, d2lb3d8e434rsy), clip metadata
  (status complete/streaming, stacked_task_clips for extend/infill).
- API surface: /api/generate/v2-web/, /api/billing/*, /api/project/me,
  /api/clips/get_songs_by_ids, /api/music_player/playbar_state,
  studio-api-prod.suno.com (Suno Studio = DAW: MIDI/effects/plugins).
