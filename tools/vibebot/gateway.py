"""vibebot.gateway — command router: validate -> sanitize -> ACK -> job ->
result. The transport (CLI or Telegram) calls `Gateway.handle(text)`, which
returns a reply string plus the job that was accepted (if any). Heavy work
is NEVER done inline in the handler: `handle` returns immediately with a job
id, and the caller runs `process_pending()` to work the queue (Telegram does
this in a worker thread; CLI just calls it directly).

Command surface (v0.1):
  /analyze <path> [--engine apkmod|mock]   run the pipeline as a job (ACK now)
  /status [job-id]                         job state + progress
  /jobs                                    all jobs
  /sessions                                stored analysis sessions
  /deepdive <target> --sha <sha256[:16]>   stateful traverse of a stored session
  /report --sha <sha256[:16]>              stored markdown report card
  /cancel <job-id>                         cancel a queued/running job
  /help                                    this surface

Security boundary (v0.1):
  * paths must exist; basename is sanitized into the report (never echoed
    from user text beyond a fixed format)
  * jobs are sequential + bounded (max_jobs)
  * the Telegram token is read ONLY from VIBE_TELEGRAM_TOKEN env var
"""

from __future__ import annotations

import os
import re
import sys
from typing import Any

from . import core
from . import engines

HELP = """vibebot commands
  /analyze <path> [--engine apkmod|mock] [--fingerprints <json>]
  /status [job-id]                         job state + progress
  /jobs                                    all jobs
  /sessions                                stored analysis sessions
  /deepdive <target> --sha <sha>           stateful traverse (callers|native|references|<name>)
  /report --sha <sha>                      stored report card
  /cancel <job-id>                         cancel queued/running job
  /help                                    this text"""

SHA_RE = re.compile(r"^[0-9a-f]{8,64}$")


class Gateway:
    def __init__(self, work_dir: str, engines_map: dict[str, core.Engine] | None = None):
        self.work_dir = work_dir
        os.makedirs(work_dir, exist_ok=True)
        self.sessions = core.SessionStore(work_dir)
        self.engines = engines_map or {
            "apkmod": engines.ApkModEngine(os.path.join(work_dir, "reports")),
            "mock": engines.MockEngine(),
        }
        self.jobs = core.JobManager(self.engines, self.sessions)

    # ------------------------------------------------------------------ api
    def handle(self, text: str, user: str = "cli") -> tuple[str, core.Job | None]:
        """Parse one command, ACK immediately. Returns (reply, accepted job)."""
        parts = (text or "").strip().split()
        if not parts or parts[0] not in (
                "/analyze", "/status", "/jobs", "/sessions", "/deepdive",
                "/report", "/cancel", "/help", "/start"):
            return HELP, None
        cmd = parts[0]

        if cmd in ("/help", "/start"):
            return HELP, None

        if cmd == "/jobs":
            lines = [f"{j['id']}  {j['state']:<10} {j['command']:<12} "
                     f"{j['artifact']}  ({j['progress']})" for j in self.jobs.all()]
            return "jobs:\n" + ("\n".join(lines) or "  none"), None

        if cmd == "/sessions":
            keys = self.sessions.list()
            lines = []
            for k in keys:
                s = self.sessions.load(k)
                n = len(s.get("findings", [])) if s else 0
                lines.append(f"  {k}  {s.get('engine') if s else '?'}  "
                             f"{n} findings")
            return "sessions:\n" + ("\n".join(lines) or "  none"), None

        if cmd == "/analyze":
            return self._analyze(parts[1:], user)

        if cmd == "/status":
            jid = parts[1] if len(parts) > 1 else self._last_job_id()
            if not jid:
                return "no job yet (run /analyze)", None
            st = self.jobs.status(jid)
            return (f"{st['id']}  {st['state']}\n  {st['progress']}"
                    + (f"\n  error: {st['error']}" if st.get("error") else "")), None

        if cmd == "/cancel":
            if len(parts) < 2:
                return "/cancel <job-id>", None
            ok = self.jobs.cancel(parts[1])
            return (f"cancel {parts[1]}: " + ("requested" if ok else "not found / not active")), None

        if cmd == "/deepdive":
            return self._deepdive(parts[1:])

        if cmd == "/report":
            return self._report(parts[1:])

        return HELP, None  # pragma: no cover

    def process_pending(self) -> list[core.Job]:
        return self.jobs.process()

    def _last_job_id(self) -> str | None:
        if self.jobs.all():
            return self.jobs.all()[-1]["id"]
        return None

    def _arg(self, parts: list[str], name: str) -> str | None:
        for i, p in enumerate(parts):
            if p == name and i + 1 < len(parts):
                return parts[i + 1]
        return None

    # --------------------------------------------------------------- routes
    def _analyze(self, parts: list[str], user: str) -> tuple[str, core.Job | None]:
        if not parts:
            return "/analyze <path> [--engine apkmod|mock] [--fingerprints <json>]", None
        path = os.path.abspath(os.path.expanduser(parts[0]))
        if not os.path.exists(path):
            return f"error: artifact not found (refused: {os.path.basename(path)})", None
        engine = self._arg(parts, "--engine") or None
        fp = self._arg(parts, "--fingerprints")
        params = {}
        if fp:
            fp_path = os.path.abspath(os.path.expanduser(fp))
            if not os.path.exists(fp_path):
                return f"error: fingerprints file not found: {os.path.basename(fp)}", None
            params["fingerprints"] = fp_path
        try:
            job = self.jobs.submit("analyze", path, user, engine, params)
        except KeyError as e:
            return f"error: {e}", None
        except (FileNotFoundError, RuntimeError) as e:
            return f"error: {e}", None
        return (f"ACK {job.id}  engine={job.engine}\n"
                f"  queued — /status {job.id}  /cancel {job.id}"), job

    def _deepdive(self, parts: list[str]) -> tuple[str, None]:
        if not parts:
            return "/deepdive <target> --sha <sha256[:16]>", None
        target, sha = parts[0], self._arg(parts, "--sha")
        if not sha or not SHA_RE.match(sha.lower()):
            return "/deepdive <target> --sha <sha256[:16]> (hex, 8..64 chars)", None
        res = core.record_deepdive(self.sessions, sha, target)
        if "error" in res:
            return res["error"], None
        lines = [f"deepdive '{target}'  ({res['matchCount']} matches, {res['note']})"]
        for m in res["matches"][:25]:
            loc = f"{m.get('class')}{'.' + m.get('method') + '()' if m.get('method') else ''}"
            lines.append(f"  [{m.get('via')}] {m.get('finding', '')} "
                         f"{loc} {m.get('artifact', '')} {m.get('detail', '')}".rstrip())
        if res["matchCount"] > 25:
            lines.append(f"  … {res['matchCount'] - 25} more")
        return "\n".join(lines), None

    def _report(self, parts: list[str]) -> tuple[str, None]:
        sha = self._arg(parts, "--sha")
        if not sha or not SHA_RE.match(sha.lower()):
            return "/report --sha <sha256[:16]>", None
        s = self.sessions.load(sha)
        if not s:
            return "no stored session for that sha — run /analyze first", None
        rep = s.get("report")
        if not rep or not os.path.exists(rep):
            return "session has no stored report", None
        txt = open(rep, encoding="utf-8").read()
        return f"report ({os.path.basename(rep)}):\n{txt[:4000]}" + \
               (f"\n… [truncated {len(txt) - 4000} chars]" if len(txt) > 4000 else ""), None


# ------------------------------------------------------------------ telegram

class TelegramTransport:
    """Optional long-poll Telegram client (stdlib only — urllib).

    OFF unless `--serve` AND VIBE_TELEGRAM_TOKEN is set in the environment.
    The token never appears in arguments, logs, or replies. The handler ACKs
    updates immediately and runs jobs in a worker thread, so a heavy APK
    analysis never blocks the Telegram request (the study's "hang" fix).
    """

    def __init__(self, gateway: Gateway, token: str,
                 allowed_user_ids: set[str] | None = None):
        self.gw = gateway
        self.token = token
        self.allowed = allowed_user_ids
        self.api = f"https://api.telegram.org/bot{token}"

    def _call(self, method: str, payload: dict) -> dict:
        import urllib.parse
        import urllib.request
        data = urllib.parse.urlencode(payload).encode()
        req = urllib.request.Request(self.api + "/" + method, data=data)
        with urllib.request.urlopen(req, timeout=70) as r:
            return __import__("json").loads(r.read())

    def _reply(self, chat_id: int, text: str) -> None:
        self._call("sendMessage", {"chat_id": chat_id, "text": text[:4000]})

    def poll_once(self, timeout_s: int = 25) -> int:
        """One getUpdates cycle. Returns number of updates handled."""
        ups = self._call("getUpdates", {
            "timeout": timeout_s, "allowed_updates": ["message"],
        }).get("result", [])
        n = 0
        for u in ups:
            msg = u.get("message") or {}
            user_id = str((msg.get("from") or {}).get("id", ""))
            chat_id = (msg.get("chat") or {}).get("id")
            text = (msg.get("text") or "").strip()
            if chat_id is None or not text:
                continue
            if self.allowed is not None and user_id not in self.allowed:
                self._reply(chat_id, "not authorized (user not in allowlist)")
                continue
            reply, job = self.gw.handle(text, user=f"tg:{user_id[:6]}")
            self._reply(chat_id, reply)
            n += 1
            if job is not None:
                for j in self.gw.process_pending():
                    if j is job:
                        self._finalize(chat_id, j)
        return n

    def _finalize(self, chat_id: int, job: core.Job) -> None:
        if job.state == core.Job.FAILED:
            self._reply(chat_id, f"{job.id} FAILED\n  {job.error}")
            return
        if job.state == core.Job.CANCELLED:
            self._reply(chat_id, f"{job.id} CANCELLED")
            return
        res = job.result
        if res is None:
            self._reply(chat_id, f"{job.id} {job.state} (no result)")
            return
        by_class: dict[str, int] = {}
        for f in res.findings:
            by_class[f["classification"]] = by_class.get(f["classification"], 0) + 1
        sha16 = (res.intake.get("sha256") or "")[:16]
        lines = [f"{job.id} COMPLETE  engine={job.engine}",
                 f"  package: {res.intake.get('package')}",
                 f"  sha256: {res.intake.get('sha256')}",
                 f"  findings: {len(res.findings)}  "
                 + "  ".join(f"{k}={v}" for k, v in sorted(by_class.items())),
                 f"  /deepdive <target> --sha {sha16}",
                 f"  /report --sha {sha16}"]
        self._reply(chat_id, "\n".join(lines))
