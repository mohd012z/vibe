# VibeBot production runtime

This directory contains a minimal systemd deployment for the Telegram runtime. It keeps the bot alive across crashes/reboots and keeps the Telegram token outside the repository.

## Host layout

- repository: `/opt/vibe`
- environment: `/etc/vibebot/vibebot.env` (mode `0600`)
- runtime state: `/var/lib/vibebot/work`
- service: `/etc/systemd/system/vibebot.service`

Create a dedicated `vibebot` system user, copy this repository to `/opt/vibe`, create `/var/lib/vibebot/work`, and make the runtime path writable by that user. Copy `deploy/vibebot.env.example` to `/etc/vibebot/vibebot.env`, replace the placeholders, then restrict it to mode `0600`.

Install `deploy/vibebot.service` as `/etc/systemd/system/vibebot.service`, run `systemctl daemon-reload`, enable/start the service, and inspect it with `systemctl status vibebot` and `journalctl -u vibebot`.

## Acceptance test

Do not treat a running process as proof that the bot works. Verify the full boundary:

1. `systemctl is-active vibebot` returns `active`.
2. Telegram `/start` returns the category console.
3. `/health` reports the transport/runtime state.
4. Upload the committed harmless fixture APK and confirm the bot acknowledges it.
5. Start analysis and confirm a terminal result is delivered.
6. Restart the service and repeat `/health`.

The production service consumes `VIBE_TELEGRAM_TOKEN` and `VIBE_BOT_ALLOWED_USERS` only from its protected environment file. Never place the real token in the repository, command line, service unit, logs, or screenshots.

## Failure triage

Trace failures in order: `systemd -> environment -> Telegram getMe/getUpdates -> TelegramTransport -> Gateway -> job -> engine -> reply`. Use the journal plus `/health`; do not add analysis engines until this chain is healthy.
