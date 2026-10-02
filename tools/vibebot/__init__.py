"""vibebot — VibeBot core v0.1: RevEngi-style analysis gateway for the vibe
workbench.

Server-side analysis architecture (study:
studies/2026-10-01-revengi-vibebot.md):

    client (CLI or Telegram)
        -> gateway (command router: validate, sanitize, ACK)
        -> job manager (async, checkpoints, cancellation)
        -> engines (apkmod adapter, mock) behind core.Engine contract
        -> normalized evidence (Finding schema, provenance on every row)
        -> session store (fingerprint -> structural map -> history)
        -> stateful /deepdive (continues the graph, never rescans)

Design rules:
  * Engines are interchangeable; the gateway/jobs never know which engine
    produced a finding — everything normalizes into core's Finding schema.
  * Evidence-first: every finding carries artifact -> location -> evidence ->
    confidence -> alternatives (falsification) -> verification.
  * Static analysis never claims execution: runtime fields stay UNKNOWN until
    observed (same ceiling as apkmod E4).
  * The Telegram transport is optional and OFF by default (token via
    VIBE_TELEGRAM_TOKEN env var only — never in source or arguments).
"""

__version__ = "0.29.0"
