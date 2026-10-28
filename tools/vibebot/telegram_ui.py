"""Telegram console model for VibeBot (compact, single-level).

Pure data/rendering layer: no network calls and no duplicate command handlers.
Callbacks resolve to existing Gateway commands so Telegram remains a transport.

Layout (v0.32, per Anam 2026-10-17 "more simple and compact"):
- HOME is ONE flat screen: every section is a tappable header row (the
  established category landmark — still drills into that section's page)
  followed by its action buttons in compact 4-per-row rows. Every action
  is one tap away; the old 2x2-tile home (two taps, duplicated actions
  across 10 categories) is gone.
- Each action appears exactly once (the old console repeated DEX in 3
  sections, Find in 2, Native in 3, Status/Sessions/Capabilities in 2,
  Deep Dive/Why?/Claims/Falsify/Report across 2–3).
- Section drill-down pages keep the previous shape (buttons + Back/Home),
  now also 4-per-row.
- Artifact-dependent buttons visibly lock (🔒) wherever they render; a
  lock tap toasts "Upload an APK/DEX first."
"""
from __future__ import annotations

from dataclasses import dataclass

BUTTONS_PER_ROW = 4  # compact rows (Telegram caps 8; 4 keeps labels legible)


@dataclass(frozen=True)
class Button:
    label: str
    callback: str
    requires_artifact: bool = False
    # v0.33: when set, render as a native URL button (client opens it in the
    # browser — no callback fires, no runtime mapping needed).
    url: str | None = None


CATEGORIES: dict[str, tuple[str, tuple[Button, ...]]] = {
    # ---- flat-home sections (order = HOME_SECTIONS) -----------------------
    "links": ("🔗 Links", (
        Button("📥 Get Link", "action:getlink"),
        Button("🔗 Upload Page", "",
               url="https://mohd012z.github.io/vibe/upload/"),
    )),
    "analyze": ("🔍 Analyze", (
        Button("🚀 Analyze", "cmd:analyze", True),
        Button("📱 APK", "cmd:apk", True),
        Button("🧬 DEX", "cmd:dex", True),
        Button("⚙ Native", "cmd:native", True),
        Button("📊 Status", "cmd:status"),
    )),
    "investigate": ("🧠 Investigate", (
        Button("🧠 Investigate", "cmd:investigate", True),
        Button("🔎 Find", "cmd:find", True),
        Button("🔗 XREF", "cmd:xref", True),
        Button("⬆ Callers", "cmd:callers", True),
        Button("⬇ Callees", "cmd:callees", True),
        Button("🔄 XMatch", "cmd:xmatch", True),
    )),
    "explore": ("🗺 Explore", (
        Button("🌳 Map", "cmd:map", True),
        Button("☕ Kotlin", "cmd:kmeta", True),
        Button("🧪 Harness", "cmd:harness"),
        Button("📜 Smali", "cmd:smali"),
    )),
    "evidence": ("🔬 Evidence", (
        Button("📋 Claims", "cmd:claims", True),
        Button("❓ Why?", "cmd:why", True),
        Button("⚔ Falsify", "cmd:falsify", True),
        Button("🧠 Deep Dive", "cmd:deepdive", True),
        Button("📄 Report", "cmd:report", True),
    )),
    "runtime": ("⚙ Runtime", (
        Button("❤️ Health", "cmd:health"),
        Button("🧰 Capabilities", "cmd:capabilities"),
        Button("📋 Jobs", "cmd:jobs"),
        Button("💾 Sessions", "cmd:sessions"),
        Button("❌ Cancel", "cmd:cancel"),
    )),
    "help": ("❓ Help", (
        Button("📖 Help", "cmd:help"),
        Button("⌨ Commands", "cmd:commands"),
    )),
    # ---- back-compat categories (not on the flat home) --------------------
    # Old home tiles pointed at these via nav:<key>; a stale tap from an
    # earlier message must still land on a useful page, never on Help.
    "artifact": ("📦 Artifact", (
        Button("📱 APK", "cmd:apk", True),
        Button("🚀 Analyze", "cmd:analyze", True),
        Button("💾 Sessions", "cmd:sessions"),
        Button("🔄 Refresh", "nav:home"),
    )),
    "code": ("🧬 Code", (
        Button("🧬 DEX", "cmd:dex", True),
        Button("📜 Smali", "cmd:smali"),
        Button("☕ Kotlin", "cmd:kmeta", True),
        Button("⚙ Native", "cmd:native", True),
        Button("🧪 Harness", "cmd:harness"),
    )),
    "reports": ("📊 Reports", (
        Button("📄 Report", "cmd:report", True),
        Button("📋 Claims", "cmd:claims", True),
        Button("⚔ Falsify", "cmd:falsify", True),
    )),
    "ask": ("💬 Ask Vibe", (
        Button("💬 Ask", "action:ask", True),
    )),
}

# The flat home, in display order. HOME is the only two-level surface:
# header row (section landmark, tappable to drill down) + action buttons.
# "ask" is intentionally NOT on the home — action:ask is a placeholder
# ("Action not implemented yet"); it stays reachable via the back-compat
# nav:ask page, and rejoining the home needs a real handler first.
HOME_SECTIONS: tuple[str, ...] = (
    "links", "analyze", "investigate", "explore", "evidence", "runtime", "help",
)


def _button_key(label: str, callback: str, locked: bool,
                url: str | None = None) -> dict:
    if url:
        return {"text": label, "url": url}
    return {
        "text": (f"🔒 {label}" if locked else label),
        "callback_data": "need:artifact" if locked else callback,
    }


def home_keyboard(has_artifact: bool = False) -> dict:
    """Telegram Bot API inline_keyboard payload for the compact home.

    One screen, zero hunting: each HOME_SECTIONS entry renders a section
    header row (callback nav:<section>) then its action buttons in
    BUTTONS_PER_ROW-per-row groups. Artifact-dependent buttons lock with
    🔒 when no artifact is selected. URL buttons (b.url set) render as
    native browser buttons — no callback, no lock.
    """
    rows = []
    for section in HOME_SECTIONS:
        title, buttons = CATEGORIES[section]
        rows.append([{"text": title, "callback_data": f"nav:{section}"}])
        for i in range(0, len(buttons), BUTTONS_PER_ROW):
            row = []
            for b in buttons[i:i + BUTTONS_PER_ROW]:
                locked = b.requires_artifact and not has_artifact
                row.append(_button_key(b.label, b.callback, locked, b.url))
            rows.append(row)
    return {"inline_keyboard": rows}


def category_keyboard(category: str, has_artifact: bool = False) -> dict:
    """Render a section drill-down page; artifact-dependent buttons lock.

    Unknown categories fall back to Help (stale nav:<key> data must never
    crash the callback handler).
    """
    if category not in CATEGORIES:
        category = "help"
    _, buttons = CATEGORIES[category]
    rows = []
    for i in range(0, len(buttons), BUTTONS_PER_ROW):
        row = []
        for b in buttons[i:i + BUTTONS_PER_ROW]:
            locked = b.requires_artifact and not has_artifact
            row.append(_button_key(b.label, b.callback, locked, b.url))
        rows.append(row)
    rows.append([
        {"text": "⬅ Back", "callback_data": "nav:home"},
        {"text": "🏠 Home", "callback_data": "nav:home"},
    ])
    return {"inline_keyboard": rows}


def home_text(artifact: dict | None = None) -> str:
    if not artifact:
        return ("🧠 VIBE — red-team analysis console\n"
                "📦 No artifact selected — upload an APK/DEX (.apk .dex .so .apks)."
                " 🔒 buttons unlock once an artifact is on file.")
    name = artifact.get("name", "artifact")
    sha = str(artifact.get("sha256", ""))[:12]
    state = artifact.get("state", "READY")
    return (f"🧠 VIBE — red-team analysis console\n"
            f"📦 {name} · 🟢 {state} · #️⃣ {sha}…")
