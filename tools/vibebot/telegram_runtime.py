"""Telegram category runtime layered over the existing transport.

Keeps Telegram as a transport: callbacks resolve to existing Gateway commands.
Adds update offsets, callback_query support, category keyboards and runtime health.
"""
from __future__ import annotations

import json
import os
import time

from . import telegram_ui
from .gateway import TelegramTransport


class CategoryTelegramTransport(TelegramTransport):
    def __init__(self, gateway, token: str, allowed_user_ids=None, worker: bool = False):
        super().__init__(gateway, token, allowed_user_ids, worker=worker)
        self.offset = 0
        self.started_at = time.time()
        self.last_rx = None
        self.last_tx = None
        self.current_artifact: dict[str, dict] = {}

    def _markup(self, keyboard: dict) -> str:
        return json.dumps(keyboard, ensure_ascii=False, separators=(",", ":"))

    def _edit(self, chat_id: int, message_id: int, text: str, keyboard: dict | None = None) -> None:
        payload = {"chat_id": chat_id, "message_id": message_id, "text": text[:4000]}
        if keyboard:
            payload["reply_markup"] = self._markup(keyboard)
        self._call("editMessageText", payload)
        self.last_tx = time.time()

    def _answer_callback(self, callback_id: str, text: str = "") -> None:
        payload = {"callback_query_id": callback_id}
        if text:
            payload["text"] = text[:180]
        self._call("answerCallbackQuery", payload)
        self.last_tx = time.time()

    def _health_text(self) -> str:
        engines = ", ".join(sorted(self.gw.engines)) or "none"
        jobs = self.gw.jobs.all()
        active = sum(1 for j in jobs if j.get("state") in ("queued", "running"))
        return ("❤️ VIBE Runtime Health\n\n"
                "Telegram      READY\n"
                "Gateway       READY\n"
                f"Engines       {engines}\n"
                f"Active jobs   {active}\n"
                f"Uptime        {int(time.time() - self.started_at)}s\n"
                f"Last RX       {'seen' if self.last_rx else 'none'}\n"
                f"Last TX       {'seen' if self.last_tx else 'none'}")

    def _artifact_for(self, user_id: str) -> dict | None:
        return self.current_artifact.get(user_id)

    def _command_for_callback(self, name: str, user_id: str) -> str | None:
        art = self._artifact_for(user_id)
        path = art.get("path") if art else None
        if name in ("analyze", "apk", "dex", "native", "kmeta", "investigate", "map"):
            return f"/{name} {path}" if path else None
        if name in ("status", "jobs", "sessions", "capabilities", "help", "commands"):
            return f"/{name}"
        # These require a target/claim/session selection. Give usage through Gateway.
        if name in ("find", "xref", "callers", "callees", "why", "deepdive", "report",
                    "claims", "falsify", "smali", "harness", "cancel"):
            return f"/{name}"
        return None

    def _handle_callback(self, cq: dict) -> None:
        callback_id = str(cq.get("id", ""))
        user_id = str((cq.get("from") or {}).get("id", ""))
        msg = cq.get("message") or {}
        chat_id = (msg.get("chat") or {}).get("id")
        message_id = msg.get("message_id")
        data = str(cq.get("data") or "")
        if chat_id is None or message_id is None:
            return
        if self.allowed is not None and user_id not in self.allowed:
            self._answer_callback(callback_id, "Not authorized")
            return
        has_artifact = self._artifact_for(user_id) is not None
        if data == "need:artifact":
            self._answer_callback(callback_id, "Upload an APK/DEX first.")
            return
        self._answer_callback(callback_id)
        if data == "nav:home":
            self._edit(chat_id, message_id, telegram_ui.home_text(self._artifact_for(user_id)),
                       telegram_ui.home_keyboard(has_artifact))
            return
        if data.startswith("nav:"):
            category = data.split(":", 1)[1]
            title = telegram_ui.CATEGORIES.get(category, telegram_ui.CATEGORIES["help"])[0]
            self._edit(chat_id, message_id, f"{title}\nChoose an action:",
                       telegram_ui.category_keyboard(category, has_artifact))
            return
        if data == "cmd:health":
            self._edit(chat_id, message_id, self._health_text(),
                       telegram_ui.category_keyboard("runtime", has_artifact))
            return
        if data.startswith("cmd:"):
            name = data.split(":", 1)[1]
            command = self._command_for_callback(name, user_id)
            if not command:
                self._edit(chat_id, message_id, "📦 Upload an APK/DEX first.",
                           telegram_ui.home_keyboard(False))
                return
            reply, job = self.gw.handle(command, user=f"tg:{user_id[:6]}")
            self._edit(chat_id, message_id, reply,
                       telegram_ui.home_keyboard(has_artifact))
            if job is not None:
                self._work_and_finalize(chat_id, job)
            return
        self._edit(chat_id, message_id, "Action not implemented yet.",
                   telegram_ui.home_keyboard(has_artifact))

    def poll_once(self, timeout_s: int = 25) -> int:
        payload = {"timeout": timeout_s,
                   "allowed_updates": ["message", "callback_query"]}
        if self.offset:
            payload["offset"] = self.offset
        updates = self._call("getUpdates", payload).get("result", [])
        handled = 0
        for update in updates:
            uid = update.get("update_id")
            if isinstance(uid, int):
                self.offset = max(self.offset, uid + 1)
            self.last_rx = time.time()
            cq = update.get("callback_query")
            if cq:
                self._handle_callback(cq)
                handled += 1
                continue
            msg = update.get("message") or {}
            user_id = str((msg.get("from") or {}).get("id", ""))
            chat_id = (msg.get("chat") or {}).get("id")
            if chat_id is None:
                continue
            if self.allowed is not None and user_id not in self.allowed:
                self._reply(chat_id, "not authorized (user not in allowlist)")
                continue
            doc = msg.get("document")
            text = (msg.get("text") or "").strip()
            if doc is not None:
                try:
                    path = self.fetch_file(doc["file_id"], doc.get("file_name", "upload.bin"))
                    self.current_artifact[user_id] = {"name": os.path.basename(path), "path": path,
                                                      "state": "READY", "sha256": ""}
                    self._reply(chat_id, telegram_ui.home_text(self.current_artifact[user_id]))
                    reply, job = self.gw.handle(f"/analyze {path}", user=f"tg:{user_id[:6]}")
                    self._reply(chat_id, reply)
                    if job is not None:
                        self._work_and_finalize(chat_id, job)
                except Exception as exc:
                    self._reply(chat_id, f"could not process upload: {exc}")
                handled += 1
                continue
            if not text:
                continue
            if text in ("/start", "/home"):
                self._call("sendMessage", {"chat_id": chat_id,
                    "text": telegram_ui.home_text(self._artifact_for(user_id)),
                    "reply_markup": self._markup(telegram_ui.home_keyboard(self._artifact_for(user_id) is not None))})
                self.last_tx = time.time()
                handled += 1
                continue
            if text == "/health":
                self._reply(chat_id, self._health_text())
                handled += 1
                continue
            try:
                reply, job = self.gw.handle(text, user=f"tg:{user_id[:6]}")
                self._reply(chat_id, reply)
                if job is not None:
                    self._work_and_finalize(chat_id, job)
            except Exception as exc:
                incident = f"TG-{int(time.time())}"
                self._reply(chat_id, f"❌ Vibe error [{incident}]\n{type(exc).__name__}: {exc}")
            handled += 1
        return handled
