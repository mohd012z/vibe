from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_systemd_service_runs_serve_mode_and_restarts():
    unit = (ROOT / "deploy" / "vibebot.service").read_text()
    assert "tools/vibebot_cli.py --serve" in unit
    assert "Restart=on-failure" in unit
    assert "EnvironmentFile=/etc/vibebot/vibebot.env" in unit
    assert "ReadWritePaths=/var/lib/vibebot" in unit


def test_systemd_unit_does_not_embed_telegram_token():
    unit = (ROOT / "deploy" / "vibebot.service").read_text()
    assert "VIBE_TELEGRAM_TOKEN=" not in unit
    assert "bot" + "Token" not in unit


def test_environment_template_has_required_runtime_keys_only_as_placeholders():
    env = (ROOT / "deploy" / "vibebot.env.example").read_text()
    assert "VIBE_TELEGRAM_TOKEN=replace_with_bot_token" in env
    assert "VIBE_BOT_ALLOWED_USERS=123456789" in env
    assert "VIBE_FILE_ROOT=/var/lib/vibebot/work" in env


def test_deploy_readme_requires_end_to_end_acceptance():
    doc = (ROOT / "deploy" / "README.md").read_text()
    for required in ("/start", "/health", "Upload", "terminal result", "Restart"):
        assert required in doc
