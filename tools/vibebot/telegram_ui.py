"""Category-driven Telegram console model for VibeBot.

Pure data/rendering layer: no network calls and no duplicate command handlers.
Callbacks resolve to existing Gateway commands so Telegram remains a transport.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Button:
    label: str
    callback: str
    requires_artifact: bool = False


CATEGORIES: dict[str, tuple[str, tuple[Button, ...]]] = {
    "artifact": ("📦 Artifact", (
        Button("ℹ Overview", "cmd:apk", True),
        Button("🕘 Sessions", "cmd:sessions"),
        Button("🔄 Refresh", "nav:home"),
    )),
    "analyze": ("🔍 Analyze", (
        Button("🚀 Smart Analyze", "cmd:analyze", True),
        Button("📱 APK", "cmd:apk", True),
        Button("🧬 DEX", "cmd:dex", True),
        Button("⚙ Native", "cmd:native", True),
        Button("📊 Status", "cmd:status"),
    )),
    "investigate": ("🧠 Investigate", (
        Button("🧠 Full Investigation", "cmd:investigate", True),
        Button("🔎 Find", "cmd:find", True),
        Button("🔗 XREF", "cmd:xref", True),
        Button("⬆ Callers", "cmd:callers", True),
        Button("⬇ Callees", "cmd:callees", True),
        Button("🔄 XMatch", "cmd:xmatch", True),
    )),
    "explore": ("🗺 Explore", (
        Button("🌳 Map", "cmd:map", True),
        Button("🔎 Find", "cmd:find", True),
        Button("🔗 References", "cmd:xref", True),
        Button("🧬 DEX", "cmd:dex", True),
        Button("⚙ Native", "cmd:native", True),
    )),
    "evidence": ("🔬 Evidence", (
        Button("📋 Claims", "cmd:claims", True),
        Button("❓ Why?", "cmd:why", True),
        Button("⚔ Falsify", "cmd:falsify", True),
        Button("🧠 Deep Dive", "cmd:deepdive", True),
    )),
    "code": ("🧬 Code", (
        Button("🧬 DEX", "cmd:dex", True),
        Button("📜 Smali", "cmd:smali"),
        Button("☕ Kotlin", "cmd:kmeta", True),
        Button("⚙ Native", "cmd:native", True),
        Button("🧪 Harness", "cmd:harness"),
    )),
    "runtime": ("⚙ Runtime", (
        Button("❤️ Health", "cmd:health"),
        Button("🧰 Capabilities", "cmd:capabilities"),
        Button("📋 Jobs", "cmd:jobs"),
        Button("⏳ Status", "cmd:status"),
        Button("💾 Sessions", "cmd:sessions"),
        Button("❌ Cancel", "cmd:cancel"),
    )),
    "reports": ("📊 Reports", (
        Button("📄 Report", "cmd:report", True),
        Button("📋 Claims", "cmd:claims", True),
        Button("⚔ Falsify", "cmd:falsify", True),
    )),
    "ask": ("💬 Ask Vibe", (
        Button("💬 Ask about artifact", "action:ask", True),
        Button("🧠 Deep Dive", "cmd:deepdive", True),
        Button("❓ Why?", "cmd:why", True),
    )),
    "help": ("❓ Help", (
        Button("📖 Help", "cmd:help"),
        Button("⌨ Commands", "cmd:commands"),
        Button("🧰 Capabilities", "cmd:capabilities"),
    )),
}


def home_keyboard(has_artifact: bool = False) -> dict:
    """Telegram Bot API inline_keyboard payload for the home dashboard."""
    rows = []
    keys = list(CATEGORIES)
    for i in range(0, len(keys), 2):
        row = []
        for key in keys[i:i + 2]:
            title = CATEGORIES[key][0]
            row.append({"text": title, "callback_data": f"nav:{key}"})
        rows.append(row)
    return {"inline_keyboard": rows}


def category_keyboard(category: str, has_artifact: bool = False) -> dict:
    """Render a category; artifact-dependent buttons visibly lock when absent."""
    if category not in CATEGORIES:
        category = "help"
    _, buttons = CATEGORIES[category]
    rows = []
    for i in range(0, len(buttons), 2):
        row = []
        for b in buttons[i:i + 2]:
            locked = b.requires_artifact and not has_artifact
            row.append({
                "text": ("🔒 " if locked else "") + b.label,
                "callback_data": "need:artifact" if locked else b.callback,
            })
        rows.append(row)
    rows.append([
        {"text": "⬅ Back", "callback_data": "nav:home"},
        {"text": "🏠 Home", "callback_data": "nav:home"},
    ])
    return {"inline_keyboard": rows}


def home_text(artifact: dict | None = None) -> str:
    if not artifact:
        return "🧠 VIBE\nAnalysis & Investigation System\n\n📦 No artifact selected\nUpload an APK/DEX or open Artifact."
    name = artifact.get("name", "artifact")
    sha = str(artifact.get("sha256", ""))[:12]
    state = artifact.get("state", "READY")
    return f"🧠 VIBE\nAnalysis & Investigation System\n\n📦 {name}\n🟢 {state}\n#️⃣ {sha}…"
