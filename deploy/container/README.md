# VibeBot container runtime

This deployment path is for users who do not operate a permanent Linux host themselves.

## Runtime contract

The container starts `python tools/vibebot_cli.py --serve` and therefore needs a continuously running container platform. The Telegram token is supplied only at runtime through `VIBE_TELEGRAM_TOKEN`; do not commit it to Git.

Required environment:

- `VIBE_TELEGRAM_TOKEN` — Telegram bot token.
- `VIBE_TELEGRAM_ALLOWLIST` — optional comma-separated authorized Telegram user/chat IDs.
- `VIBE_FILE_ROOT=/data` — container artifact workspace.

Persistent storage should be mounted at `/data`.

## Local/container smoke test

```sh
export VIBE_TELEGRAM_TOKEN='set-this-outside-git'
docker compose build
docker compose up -d
docker compose logs --tail=100 vibebot
```

Then test in Telegram:

1. `/start` must return the category dashboard.
2. `/health` must return runtime health.
3. Upload an APK/DEX and confirm acknowledgement.
4. Run Analyze and confirm a terminal success or failure response.
5. Restart the container and repeat `/health`.

## Hosting requirements

Choose a platform that can run a continuously active Docker/container workload and provide persistent storage. Vibe's heavier APK/DEX/native analyzers may require more CPU, memory, system packages, or Android/native tooling than the minimal image currently installs. Treat `/health` and `/capabilities` as the runtime truth and add analyzer dependencies only when their absence is demonstrated.

Do not use a request-only serverless function as the primary long-polling runtime unless the Telegram transport is redesigned around webhooks.
