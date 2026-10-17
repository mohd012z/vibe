import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.path.join(ROOT, "tools")
if TOOLS not in sys.path:
    sys.path.insert(0, TOOLS)

from vibebot import engines, gateway
from vibebot.telegram_runtime import CategoryTelegramTransport


class FakeTelegram(CategoryTelegramTransport):
    def __init__(self, gw, updates):
        super().__init__(gw, "test-token", None)
        self.updates = updates
        self.calls = []

    def _call(self, method, payload):
        self.calls.append((method, payload))
        if method == "getUpdates":
            return {"ok": True, "result": self.updates}
        return {"ok": True, "result": True}


def _gateway(td):
    return gateway.Gateway(td, {"mock": engines.MockEngine()})


def test_poll_requests_messages_and_callbacks_and_advances_offset():
    with tempfile.TemporaryDirectory() as td:
        t = FakeTelegram(_gateway(td), [{"update_id": 41, "callback_query": {
            "id": "cb1", "from": {"id": 7}, "message": {"chat": {"id": 9}, "message_id": 3},
            "data": "nav:runtime"}}])
        assert t.poll_once(0) == 1
        get = next(p for m, p in t.calls if m == "getUpdates")
        assert get["allowed_updates"] == ["message", "callback_query"]
        assert t.offset == 42
        assert any(m == "answerCallbackQuery" for m, _ in t.calls)
        assert any(m == "editMessageText" for m, _ in t.calls)


def test_health_callback_returns_runtime_health():
    with tempfile.TemporaryDirectory() as td:
        t = FakeTelegram(_gateway(td), [{"update_id": 1, "callback_query": {
            "id": "cb2", "from": {"id": 7}, "message": {"chat": {"id": 9}, "message_id": 3},
            "data": "cmd:health"}}])
        t.poll_once(0)
        edits = [p for m, p in t.calls if m == "editMessageText"]
        assert edits
        assert "VIBE Runtime Health" in edits[-1]["text"]
        assert "Telegram" in edits[-1]["text"]
        assert "Gateway" in edits[-1]["text"]


def test_locked_artifact_callback_explains_upload_requirement():
    with tempfile.TemporaryDirectory() as td:
        t = FakeTelegram(_gateway(td), [{"update_id": 2, "callback_query": {
            "id": "cb3", "from": {"id": 7}, "message": {"chat": {"id": 9}, "message_id": 3},
            "data": "need:artifact"}}])
        t.poll_once(0)
        answers = [p for m, p in t.calls if m == "answerCallbackQuery"]
        assert any("Upload" in p.get("text", "") for p in answers)


def test_callback_name_coverage_for_flat_home():
    # Every cmd:* button on the flat home must map to a real gateway command
    # (or an honest usage reply) — a name missing from the mapping silently
    # renders as "Upload an APK/DEX first." / falls to the not-implemented
    # catch-all, and the flat home has no second level to hide it in.
    from vibebot import telegram_ui
    names = set()
    for _, (_, buttons) in telegram_ui.CATEGORIES.items():
        for b in buttons:
            if b.callback.startswith("cmd:"):
                names.add(b.callback.split(":", 1)[1])
    with tempfile.TemporaryDirectory() as td:
        gw = _gateway(td)
        t = FakeTelegram(gw, [])
        t.current_artifact = {"7": {"name": "a.apk", "path": os.path.join(td, "a.apk"),
                                    "state": "READY", "sha256": "x" * 64}}
        # health is special-cased in _handle_callback (renders the runtime
        # health page directly) and never reaches the command mapping.
        names.discard("health")
        # with an artifact, every name resolves to a command string
        for n in sorted(names):
            assert t._command_for_callback(n, "7") is not None, n
        del t.current_artifact["7"]
        # without one: artifact-dependent single-artifact names resolve to
        # None (lock). (xmatch takes usage "/xmatch" either way — its lock
        # lives in the UI layer, and it needs two artifacts.)
        resolved_none = {n for n in names if t._command_for_callback(n, "7") is None}
        assert "analyze" in resolved_none and "map" in resolved_none, resolved_none
        for n in ("status", "jobs", "help", "commands", "capabilities"):
            assert t._command_for_callback(n, "7") is not None, n
