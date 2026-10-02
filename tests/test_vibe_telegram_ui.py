import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.path.join(ROOT, "tools")
if TOOLS not in sys.path:
    sys.path.insert(0, TOOLS)

from vibebot import telegram_ui


def test_home_has_expected_categories():
    kb = telegram_ui.home_keyboard()
    callbacks = [b["callback_data"] for row in kb["inline_keyboard"] for b in row]
    for name in ("artifact", "analyze", "investigate", "explore", "evidence",
                 "code", "runtime", "reports", "ask", "help"):
        assert f"nav:{name}" in callbacks


def test_artifact_actions_lock_without_artifact():
    kb = telegram_ui.category_keyboard("analyze", has_artifact=False)
    buttons = [b for row in kb["inline_keyboard"] for b in row]
    assert any(b["callback_data"] == "need:artifact" for b in buttons)
    assert any(b["callback_data"] == "cmd:status" for b in buttons)


def test_artifact_actions_unlock_with_artifact():
    kb = telegram_ui.category_keyboard("analyze", has_artifact=True)
    callbacks = [b["callback_data"] for row in kb["inline_keyboard"] for b in row]
    assert "cmd:analyze" in callbacks
    assert "cmd:dex" in callbacks
    assert "cmd:native" in callbacks


def test_unknown_category_falls_back_to_help():
    kb = telegram_ui.category_keyboard("does-not-exist")
    callbacks = [b["callback_data"] for row in kb["inline_keyboard"] for b in row]
    assert "cmd:help" in callbacks


def test_home_text_artifact_state():
    text = telegram_ui.home_text({"name": "demo.apk", "sha256": "abcdef1234567890", "state": "READY"})
    assert "demo.apk" in text
    assert "abcdef123456" in text
    assert "READY" in text
