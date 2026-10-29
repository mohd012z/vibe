# Study note — FreeLLMAPI ecosystem deep-dive: yawo/freellmapi-proxy + lov0u/freellmapi + awesome-freellm-apis (2026-10-28)

Anam's input: "study and learn deeper, find all method useful to implement in
**lola** and **vibe ai**" — 3 links. Follow-up to the tashfeenahmed/freellmapi
study (Path B chosen: in-process stdlib router, OpenAI-compatible shape).
All three cloned 2026-10-28, read as DATA.

## The three repos in one line each

1. **yawo/freellmapi-proxy** (39M) — a FreeLLMAPI fork/continuation (11
   providers, ~1.3B tokens) that adds the **key asset: `server-rs/` = a full
   Rust rewrite, 2,086 lines, explicitly targeted at Termux on Android
   (`aarch64-linux-android`) per `RUST_MIGRATION_PLAN.md`.**
2. **lov0u/freellmapi** (19M) — a snapshot fork (29 providers, 358
   endpoints, ~4B tokens). Same Node architecture as tashfeenahmed; confirms
   the pattern, no new mechanism.
3. **open-free-llm-api/awesome-freellm-apis** (436K) — NOT code, a
   **machine-readable, daily-updated directory** of 513+ free LLM APIs / 30
   providers (freellm.net): parseable tables (BEGIN/END markers) of base
   URLs, credit-card requirements, rate limits, best models, top-by-weekly-
   usage, plus a local/self-hosted section.

## #1 yawo/freellmapi-proxy — the Rust port (the reusable engine)

This is the one to mine. It's a clean, small, portable reference
implementation of the whole router in Rust — and it's aimed at Android/Termux,
i.e. it's already shaped for an on-device router. Structure (20 .rs files):

- **`providers/base.rs` — the `Provider` trait** (26 lines):
  `platform()`, `chat_completion(key,req)`, `stream_chat_completion(key,req)
  → BoxStream<Event>`, `validate_key(key)`. Two impls:
  - `openai_compat.rs` (162 lines) — ONE adapter covers Groq/Cerebras/
    Mistral/OpenRouter/etc (they're all OpenAI-compatible); streaming via
    `reqwest_eventsource` SSE; a `normalize_choices()` shim for providers
    that shape choices differently.
  - `google.rs` (403 lines) — the ONLY provider needing bespoke translation
    (Gemini's native format ≠ OpenAI), so the pattern is "95% share one
    adapter, the odd one gets a translator."
- **`services/ratelimit.rs` (131 lines)** — 4-window sliding limits
  (request/token × minute/day) + **429 cooldown** (`set_cooldown` /
  `is_on_cooldown`) + `prune_*` timestamp GC. Simple, correct, in-memory
  (`DashMap`/`RwLock`).
- **`services/router.rs` (208 lines)** — the fallback chain: load
  `fallback_config` ordered by `priority`, compute effective order as
  `priority + penalty`, where `penalty += PENALTY_PER_429` (capped
  `MAX_PENALTY`) on each rate-limit hit, `-1` per success, and **decays over
  time** (`decay_steps × DECAY_AMOUNT`). Pick first non-cooled-down key.
  → This is a SIMPLER, proven alternative to tashfeenahmed's Thompson
  sampling: **penalty-ranked fallback with 429 decay.** ~60 lines of logic.
- **`crypto.rs` (111 lines)** — AES-256-GCM for encrypted key storage,
  deliberately byte-compatible with the Node impl so existing keys stay
  valid; `mask_key()` for display.
- **`proxy.rs` (234 lines)** — `/v1/chat/completions`: `stream:true` → SSE,
  else JSON; drives the router + a failover loop.
- **`services/health.rs` (79 lines)** — background `tokio::spawn` loop that
  periodically validates keys (pre-warms the penalty state).
- **`main.rs`** — Axum + tokio; serves `client/dist` with SPA fallback.

**Stack (decided, in the plan):** Axum + tokio, SeaORM + sqlx-sqlite,
reqwest, serde, aes-gcm, axum-extra (SSE), dotenvy. Cross-compile target
`aarch64-linux-android`.

## #3 awesome-freellm-apis — the catalog DATA (the seed list)

Parse-ready tables between `<!-- BEGIN_* -->`/`<!-- END_* -->` markers:
- **`PERMANENT_FREE`** — 28 providers, no-card tier (NVIDIA NIM 134 models/
  1M ctx/40RPM, Google Gemini 19/1M, Cloudflare 41/262K, Groq 12/262K,
  Cerebras, Mistral, Cohere, Z.ai, HF, DeepSeek, …) vs credit-card required.
- **`QUICK_REF`** — exact **base URL** per provider (e.g. Groq
  `https://api.groq.com/openai/v1`, Gemini
  `https://generativelanguage.googleapis.com/v1beta`, OpenRouter
  `https://openrouter.ai/api/v1`, Cerebras `https://api.cerebras.ai/v1`).
- **`BEST_MODELS`** — best free model per provider + model ID + ctx + rate
  limit (Gemini 3.8 Flash, GLM-5.2, Kimi K2, gpt-oss-20b, Qwen3.5,
  Nemotron 3 Ultra 550B, …).
- **`TOP_MODELS`** — top by weekly usage (usage = which ones are actually
  working right now).
- **Local/self-hosted** — Ollama / LM Studio / llama.cpp / GPT4All / Jan /
  KoboldCpp (unlimited, private, free forever — the on-device path).
- **The `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` trick** (in code-examples/):
  point Claude Code / Codex / Cursor at ANY free OpenAI-compatible backend
  by setting two env vars — **zero code changes** to the client.

## THE two highest-leverage methods (for BOTH lola + vibe ai)

**M1 — The `*_BASE_URL` env redirect (zero-code attach).**
Both Claude Code and Codex (and any OpenAI-SDK client) read
`{ANTHROPIC|OPENAI}_BASE_URL` + `{ANTHROPIC|OPENAI}_AUTH_TOKEN` /
`OPENAI_API_KEY`. Set them to a free backend and the client just works.
- For **vibe ai**: the bot's LLM client (whichever we build, Path B) and any
  coding agent we run against APKs point at the free router by env var only.
- For **lola**: its bundled agent/LLM client can be pointed at a free cloud
  fallback (or the on-device router) with two env vars, no recompile.
→ This is the cheapest possible "add an LLM" and it's already proven to work
with our exact tooling.

**M2 — The on-device Rust router (lola's killer feature).**
yawo's `server-rs` is a ~2K-line, single-binary, cross-compiles-to-android
LLM router. lola ALREADY bundles llama.cpp (Qwen3 0.6B, LOCAL_ONLY, OpenAI-
compatible endpoint) + has the native/Android muscle. The move: run the Rust
router **on-device** (or as a thin companion) so lola's local model is
endpoint #1 in a fallback chain with free cloud tiers (Groq/Cerebras/
Google/OpenRouter) behind it. Local = private + unlimited but small; cloud
free-tier = bigger model when local can't handle it or is busy. The
`priority + 429-penalty-decay` fallback + 4-window quota + AES-GCM key
storage port 1:1. This is the "local-first, cloud-fallback" LLM that makes
lola genuinely useful offline AND capable online without a paid key.

## What to port to vibe ai (VibeBot item #9, Path B — confirmed shape)

The Rust `router.rs` + `ratelimit.rs` are the reference for `tools/vibebot/
llm.py` (stdlib Python, in-process, no Node):
- Endpoint list seeded from awesome-freellm-apis `QUICK_REF` (base_url +
  model_id + ctx + rate limit), keys from env, stored AES-GCM-encrypted in a
  SQLite file (or our state.db) with `mask_key()` display.
- Fallback = `priority + penalty`; `penalty += N` on 429 (capped), `-1` on
  success, time-decay; skip on-cooldown endpoints. (Simpler than Thompson
  sampling; upgrade later if we want.)
- 4-window quota (RPM/TPM/RPD/TPD) per (provider, model, key) + in-flight
  leases (from tashfeenahmed study) to close the concurrency gap.
- One `OpenAICompat` client (requests + manual SSE line-parse) covers ~all
  providers; a Gemini translator for the Google-native path.
- Background health pre-warm (optional) = the `health.rs` loop.
- Expose `/ask <q>` (and let /apk /find /claims attach their structured
  findings as prompt context — grounded, not raw bytes).

## What is NOT worth copying

- lov0u's whole Node app (duplicate of tashfeenahmed; use it only as a
  second confirmation the architecture is stable across forks).
- The freellm.co / freellm.net SaaS + premium signed feed (that's their
  business, not ours — we seed from the open awesome-* tables + update
  manually or via a small daily fetch).
- The React dashboard (we have a Telegram UI; a `/models` + `/keys` bot
  command replaces it).

## Provenance

- yawo/freellmapi-proxy @ main (2026-10-28), `server-rs/` (20 .rs, 2086
  lines) + `RUST_MIGRATION_PLAN.md` (93 lines) — Rust port read directly.
- lov0u/freellmapi @ main (29 providers snapshot) — README + tree.
- open-free-llm-api/awesome-freellm-apis @ main (README 37K, daily-updated
  2026-10-20) — tables parsed; `code-examples/{claude-code,codex,cursor}.md`.
- None executed (Rust port not built here — no cargo/android target set up;
  mechanisms read from source). MIT (yawo/lov0u), the awesome list has its
  own license — verify before vendoring data.
