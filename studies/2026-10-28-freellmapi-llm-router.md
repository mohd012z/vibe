# Study note — tashfeenahmed/freellmapi (FreeLLMAPI) (2026-10-28)

Anam's input: "study and learn deeper to add ai bot llm inside telegram bot to
assist any inquiry, find useful method to implement
https://github.com/tashfeenahmed/freellmapi". Treated as DATA. Cloned
2026-10-28 (MIT), read README + architecture docs + API contract.

## What it is (one line)

A self-hosted Node.js router that aggregates **34 free LLM providers / 635
free endpoints (~7.4B free tokens/month stacked)** behind ONE
**OpenAI-compatible `/v1` endpoint**: `POST /v1/chat/completions` with
`model: "auto"` → the router picks the best (platform, model, key) triple,
fails over across providers on rate-limit/error, tracks per-key quotas, and
streams OpenAI-format SSE back. Keys stored encrypted in SQLite. A signed
catalog feed keeps the model list current (free = monthly snapshot, premium
$19/yr = same-day).

## Why it matters for our Telegram bot (the point)

VibeBot's queued backlog item #9 is "AI chatbot to analyze apk in detail …
for training purpose". The bot today is pure static analysis (no LLM —
claims/E-levels are computed, not generated). FreeLLMAPI is the **LLM
backbone** that makes a natural-language assistant possible WITHOUT a paid
API key: point one OpenAI-compatible client at a local FreeLLMAPI and the
34 free tiers pool together. It's the cheapest "always-on, quota-managed"
answer to "assist any inquiry".

## The reusable mechanisms (the actually-useful methods)

These are the transferable patterns — NOT the Node app itself:

1. **OpenAI-compatible `/v1/chat/completions` as the universal client
   contract.** Every client (curl, python `openai`, Node SDK, coding agents)
   just sets `base_url` + `api_key`. `model: "auto"` = router decides.
   Suffixes steer per-request without config changes: `auto:fast`,
   `auto:smart`, `auto:cheap`, `auto:reliable`, `auto:balanced`,
   `auto:<profile-name>` (named fallback chains). **This is the one thing to
   copy verbatim for VibeBot:** whatever LLM we wire in, expose it as an
   OpenAI-compatible endpoint (or just call one) so the bot + any future
   tool share the same client code.

2. **Contextual-bandit routing (Thompson sampling over a Beta posterior),
   not round-robin.** `score = w_rel·reliability + w_speed·speed +
   w_intel·intelligence`, then `× headroomFactor × rateLimitFactor`
   (guardrail multipliers in [floor,1]). Reliability = decay-weighted
   (2-day half-life, 7-day window) `sampleBeta(α,β)` where α/β fold in
   successes/failures (+ opt-in community prior, capped at 50 effective
   samples so local evidence dominates). Strategy is selectable
   (balanced/smartest/fastest/reliable/priority/decision). **Portable
   lesson:** for ANY multi-provider LLM use, keep a per-endpoint Beta
   posterior updated from live success/failure + latency, and pick by
   sampled score — you get self-healing failover with ~40 lines of Python,
   no ML framework.

3. **Four-window quota accounting + in-flight leases.** Per
   (platform, model, key): RPM (60 s sliding), RPD (UTC-day), TPM (60 s),
   TPD (UTC-day). Plus provider-wide shared pools (e.g. OpenRouter
   1000/day, NVIDIA 40 RPM account-wide). The subtle bug they close:
   **provisional leases** — between key-selection and the post-success
   write, N concurrent requests would all read the same pre-check and blow
   the limit; a lease makes in-flight requests visible (`acquireLease` /
   `releaseLease` in `finally`, idempotent, 2-min max-age backstop).
   **Portable lesson:** any self-made quota gate needs in-flight leases,
   or concurrency will overrun free tiers.

4. **Failover with a wall-clock retry budget + hedging.** Default 45 s
   `FALLBACK_TIME_BUDGET_MS`, checked before each retry; attempt 0 AND
   attempt 1 always run (so one failover hop is structurally possible).
   When the budget expires mid-attempt, **hedge** = `AbortController`
   cancels the stalled upstream fetch (a "HedgeAbortError" is NOT a
   provider-health failure → no cooldown penalty). Streaming disarms the
   hedge on first byte. Optional circuit-breaker (`max_consecutive_upstream_
   fails`) → 503 "upstream_unhealthy". **Portable lesson:** bound total
   failover time, always allow exactly one hop, and abort-in-flight (not
   just "don't start the next") so one slow provider can't stall the chain.

5. **Degraded-mode state machine with hysteresis.** Tracks
   healthy-provider ratio; normal→degraded after staying below
   `DEGRADED_HEALTHY_RATIO` (0.5) for `ENTRY_GRACE_MS` (60 s), degraded→
   normal only after above for `EXIT_GRACE_MS` (120 s, longer = hysteresis,
   no flapping). In degraded mode: bandit exploration disabled, sticks to
   scored order of remaining healthy providers. `unknown` (unprobed) keys
   count as healthy. **Portable lesson:** hysteresis (different entry/exit
   thresholds + grace periods) is what stops a flapping router; `unknown`
   ≠ dead.

6. **`X-Fallback-Detail` observability header.** `platform/model keyN=
   outcome t=startOffset+durationMs msg=summary; +N more` — which hops
   burned and how long each cost. Opt-in, 2048-char budget, failed hops
   only. **Portable lesson:** log the failover TRAIL (per-hop timing +
   redacted error), not just the winner — that's the only way to debug "why
   was this 40 s" later.

## What NOT to copy (honest gaps)

- The Node/SQLite/dashboard stack as a whole — for VibeBot we want stdlib
  Python in the bot process, not a second long-running Node service (unless
  we adopt the full router, which is the "batteries-included" option below).
- The signed catalog feed + freellmapi.co premium (that's their SaaS).
- 34-provider provider adapters (we need only the 3–5 with the best free
  tiers: Google AI Studio, Groq, Cerebras, OpenRouter-free, Cloudflare).

## Two implementation paths for the Telegram bot (VibeBot item #9)

**Path A — adopt the router (batteries-included):**
`docker compose up` FreeLLMAPI on the host (it's a single container,
`ghcr.io/freellmapi`), add 3–5 free provider keys, then VibeBot's `/ask`
just `POST {base}/v1/chat/completions` with `model: "auto"`. Pros: quota
tracking, bandit failover, streaming, degraded-mode — all done. Cons: extra
service to run + Node dependency + free-tier caps still apply.

**Path B — port the pattern (stdlib, in-process, our style):**
A small `tools/vibebot/llm.py` (~200 lines): a list of OpenAI-compatible
endpoints (base_url + model + key from env), a per-endpoint Beta posterior
(decay-weighted success/latency), 4-window quota + leases, one-hopped
failover with a wall-clock budget + abort, and a `complete(messages,
purpose)` function the bot calls. Expose `/ask <question>` (and let `/apk`,
`/find`, `/claims` attach their structured findings as the prompt context).
Pros: no new service, fits our stdlib-first bot, we own the evidence.
Cons: we maintain the provider list. **Recommendation: Path B for the bot
(now), with the request/response shape kept OpenAI-compatible so Path A can
replace the backend transparently later.**

## The prompt-design note (for "assist any inquiry" on APKs)

Feed the LLM the bot's OWN structured findings, not raw bytes: the
`/claims` board (claim + E-level), the `/find` hit list, the `/xref`
caller/callee map, the manifest components. The LLM's job is to EXPLAIN +
SUGGEST (VIP gate, ad module, what to patch) over evidence we already
computed — that keeps it grounded (matches the evidence-first style) and
cheap on tokens. A `purpose` tag per request (explain / suggest-patch /
summarize) maps to a different system prompt + a different `auto:`
strategy (e.g. `auto:smart` for explain, `auto:fast` for summarize).

## Provenance

- Repo: github.com/tashfeenahmed/freellmapi @ main (2026-10-28), MIT.
- Read: README (61 KB), `docs/en/architecture/01-routing-and-bandit-
  scoring.md`, `02-quota-and-cooldown-engine.md`, `04-degraded-mode-and-
  failover.md`, `docs/en/api/01-rest-api.md`. Server source layout
  (`server/src/services/{router,scoring,ratelimit,degradation,fallback-
  loop}.ts`) confirmed as the source of record for each mechanism.
- Not executed here (Node router; would need `docker`/`npm` + provider
  keys). Mechanisms read from docs + confirmed present in the source tree.
