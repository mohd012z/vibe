import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.path.join(ROOT, "tools")
if TOOLS not in sys.path:
    sys.path.insert(0, TOOLS)

from vibebot import telegram_ui

# v0.32 compact home: flat sections in display order.
HOME_ORDER = ("links", "analyze", "investigate", "explore", "evidence",
              "runtime", "help")


def _all_callbacks(kb):
    # v0.33: URL buttons carry no callback_data (native browser button) —
    # skip them here; they are asserted on their own.
    return [b["callback_data"] for row in kb["inline_keyboard"] for b in row
            if "callback_data" in b]


def test_home_is_flat_sections_in_order():
    kb = telegram_ui.home_keyboard()
    rows = kb["inline_keyboard"]
    # Section header rows carry callback nav:<section>, in HOME_ORDER.
    headers = [b["callback_data"] for row in rows for b in row
               if b.get("callback_data", "").startswith("nav:")]
    assert headers == [f"nav:{s}" for s in HOME_ORDER], headers


def test_home_every_action_one_tap_away():
    kb = telegram_ui.home_keyboard(has_artifact=True)
    callbacks = _all_callbacks(kb)
    # Core console actions must all be reachable without a drill-down tap.
    for cb in ("cmd:analyze", "cmd:apk", "cmd:dex", "cmd:native", "cmd:status",
               "cmd:investigate", "cmd:find", "cmd:xref", "cmd:callers",
               "cmd:callees", "cmd:xmatch", "cmd:map", "cmd:kmeta", "cmd:harness",
               "cmd:claims", "cmd:why", "cmd:falsify", "cmd:deepdive", "cmd:report",
               "cmd:health", "cmd:capabilities", "cmd:jobs", "cmd:sessions",
               "cmd:cancel", "cmd:help", "cmd:commands"):
        assert cb in callbacks, f"home missing {cb}"


def test_home_no_duplicate_actions():
    # The old console repeated DEX/Native/Status/Sessions/etc. across
    # categories; the compact home renders each action exactly once.
    kb = telegram_ui.home_keyboard(has_artifact=True)
    cmds = [c for c in _all_callbacks(kb) if c.startswith("cmd:")]
    assert len(cmds) == len(set(cmds)), sorted(c for c in cmds if cmds.count(c) > 1)


def test_home_rows_are_compact():
    # 4-per-row action rows (Telegram allows up to 8); section headers are
    # single-cell rows.
    kb = telegram_ui.home_keyboard()
    for row in kb["inline_keyboard"]:
        assert 1 <= len(row) <= 4, row
    # Bounded total row count (the flat home is one screen, not a wall).
    # v0.33: +1 section row (🔗 Links: Get Link + Upload Page, 2 rows) -> 19.
    assert len(kb["inline_keyboard"]) <= 19


def test_artifact_actions_lock_on_home_without_artifact():
    kb = telegram_ui.home_keyboard(has_artifact=False)
    callbacks = _all_callbacks(kb)
    assert "need:artifact" in callbacks
    # Locked home buttons must NOT expose the real callback.
    for cb in ("cmd:analyze", "cmd:apk", "cmd:dex", "cmd:native",
               "cmd:find", "cmd:claims", "cmd:report"):
        assert cb not in callbacks, f"{cb} should be locked"
    # Unlocked home buttons must stay reachable.
    for cb in ("cmd:status", "cmd:jobs", "cmd:help", "cmd:capabilities"):
        assert cb in callbacks, f"{cb} should be unlocked"


def test_artifact_actions_unlock_with_artifact():
    kb = telegram_ui.home_keyboard(has_artifact=True)
    callbacks = _all_callbacks(kb)
    assert "cmd:analyze" in callbacks
    assert "cmd:dex" in callbacks
    assert "cmd:native" in callbacks
    assert "need:artifact" not in callbacks


def test_category_keyboard_locks_and_back_nav():
    kb = telegram_ui.category_keyboard("analyze", has_artifact=False)
    buttons = [b for row in kb["inline_keyboard"] for b in row]
    assert any(b["callback_data"] == "need:artifact" for b in buttons)
    assert any(b["callback_data"] == "cmd:status" for b in buttons)
    # Drill-down page always ends with Back/Home.
    last = kb["inline_keyboard"][-1]
    assert all(b["callback_data"] == "nav:home" for b in last)


def test_back_compat_categories_still_resolve():
    # Stale nav:<key> taps from pre-compact messages must land on real
    # sections (never the Help fallback).
    for key in ("artifact", "code", "reports", "ask"):
        assert key in telegram_ui.CATEGORIES, key
    kb = telegram_ui.category_keyboard("artifact", has_artifact=True)
    assert any(b["callback_data"] == "cmd:apk" for row in kb["inline_keyboard"] for b in row)


def test_unknown_category_falls_back_to_help():
    kb = telegram_ui.category_keyboard("does-not-exist")
    callbacks = _all_callbacks(kb)
    assert "cmd:help" in callbacks


def test_home_text_artifact_state():
    text = telegram_ui.home_text({"name": "demo.apk", "sha256": "abcdef1234567890", "state": "READY"})
    assert "demo.apk" in text
    assert "abcdef123456" in text
    assert "READY" in text


def test_home_text_no_artifact_mentions_upload():
    text = telegram_ui.home_text(None)
    assert "No artifact" in text
    assert "upload" in text.lower()
