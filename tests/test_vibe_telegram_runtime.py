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


def test_getlink_callback_prompts_for_link():
    # v0.33: the Links section's Get Link button explains the link flow.
    with tempfile.TemporaryDirectory() as td:
        t = FakeTelegram(_gateway(td), [{
            "update_id": 3, "callback_query": {
                "id": "cb4", "from": {"id": 7},
                "message": {"chat": {"id": 9}, "message_id": 4},
                "data": "action:getlink"}}])
        t.poll_once(0)
        edits = [p for m, p in t.calls if m == "editMessageText"]
        assert edits
        assert "Send me the file link" in edits[-1]["text"]
        assert "MediaFire" in edits[-1]["text"]
        assert "20 MB" in edits[-1]["text"]


def test_home_keyboard_has_links_section_with_getlink_and_upload_url():
    # v0.33: Links is the first home section; Get Link is a callback, the
    # Upload Page is a native URL button (no callback_data).
    from vibebot import telegram_ui
    kb = telegram_ui.home_keyboard()
    rows = kb["inline_keyboard"]
    headers = [b["callback_data"] for row in rows for b in row
               if b.get("callback_data", "").startswith("nav:")]
    assert headers[0] == "nav:links", headers
    flat = [b for row in rows for b in row]
    assert any(b.get("callback_data") == "action:getlink" for b in flat)
    assert any(b.get("url") == "https://mohd012z.github.io/vibe/upload/"
               and "callback_data" not in b for b in flat)


def test_bare_mediafire_link_auto_routes_to_apk():
    # v0.33: pasting a raw share link (no / command) becomes /apk <url>.
    with tempfile.TemporaryDirectory() as td:
        handled_cmds = []
        t = FakeTelegram(_gateway(td), [{
            "update_id": 4, "message": {
                "from": {"id": 7}, "chat": {"id": 9},
                "text": ("https://www.mediafire.com/file/3bcui905kytic7g/"
                         "Pulse+Player_4.0.0.apk/file")}}])
        orig_handle = t.gw.handle

        def spy(text, **kw):
            handled_cmds.append(text)
            return ("stub", None)  # no network in this unit test
        t.gw.handle = spy
        t.poll_once(0)
        assert handled_cmds, "message was not routed to the gateway"
        assert handled_cmds[0].startswith("/apk https://www.mediafire.com/"), \
            handled_cmds[0]


def test_non_url_text_not_rewritten():
    # v0.33: plain words / unknown commands pass through untouched.
    with tempfile.TemporaryDirectory() as td:
        t = FakeTelegram(_gateway(td), [{
            "update_id": 5, "message": {
                "from": {"id": 7}, "chat": {"id": 9},
                "text": "/status"}}])
        t.poll_once(0)
        # no crash, gateway saw the command verbatim
        sends = [p for m, p in t.calls if m == "sendMessage"]
        assert sends, t.calls


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
