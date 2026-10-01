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
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any

from . import core
from . import engines

HELP = """vibebot commands
  /apk <path>            APK overview + Vibe IR entity graph (stable IDs)
  /map <path>            entity graph tree + cross-layer paths (or --sha <…>)
  /find <text> --sha <…> TargetFinder: strings/resources/classes/methods/components
  /xref <M|Cls.m> --sha <…>  references: callers + callees + strings
  /callers <M|Cls.m> --sha <…>  who calls this method (Used By)
  /callees <M|Cls.m> --sha <…>  what this method calls (Uses)
  /claims [--sha <…>]    Evidence board: every claim + state + E-level
  /why <C-id> [--sha <…>] CodeTransparent trace: claim -> evidence -> bytes
  /plan <goal>           cheapest-capable method plan (live providers)
  /capabilities          what's installed here (honest detection)
  /analyze <path> [--engine apkmod|dexmapper] [--fingerprints <json>]
  /dex <path>            DEX Mapper job: class->method->call map + JNI + integrity
  /smali <name|0x..|substr>   query the Dalvik opcode table
  /base <value> <from> <to>   convert between number bases (2..36)
  /hash <text>           sha256 of a text string
  /dexcheck <path>       validate DEX headers (sha1 + adler32 + version)
  /dexrepair <path>      report what /dexrepair would fix (dry-run, read-only)
  /status [job-id]       job state + progress
  /jobs                  all jobs
  /sessions              stored analysis sessions
  /deepdive <target> --sha <sha>   stateful traverse (callers|native|references|<name>|jni|calls)
  /investigate <path> [target]     orchestrated 18-stage investigation (job)
  /report --sha <sha>    stored report card
  /cancel <job-id>       cancel queued/running job
  /help                  this text

P2 note: /asm and raw-hex /disasm are deferred to P3 (bit-level Dalvik
encode/decode needs a ground-truth decoder cross-check; see study note)."""

SHA_RE = re.compile(r"^[0-9a-f]{8,64}$")

MAX_UPLOAD_BYTES = 200 * 1024 * 1024


def sanitize_filename(name: str, max_len: int = 80) -> str:
    """Reduce an inbound file name to a safe on-disk name (no path, no
    shell metachars, bounded length). Returns 'upload.bin' if nothing safe."""
    base = os.path.basename(name or "").strip()
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)
    base = base[:max_len].strip("._")
    return base or "upload.bin"


class Gateway:
    def __init__(self, work_dir: str, engines_map: dict[str, core.Engine] | None = None):
        self.work_dir = work_dir
        os.makedirs(work_dir, exist_ok=True)
        self.sessions = core.SessionStore(work_dir)
        self.engines = engines_map or self._default_engines()
        self.jobs = core.JobManager(self.engines, self.sessions)

    def _default_engines(self) -> dict[str, core.Engine]:
        m = {"apkmod": engines.ApkModEngine(os.path.join(self.work_dir, "reports")),
             "mock": engines.MockEngine()}
        # graph + dexmapper need androguard; register only if present so a
        # stdlib-only env still works (mock + apkmod-intake).
        try:
            from . import dexmapper
            if dexmapper._androguard():
                m["dexmapper"] = dexmapper.DexMapperEngine(
                    os.path.join(self.work_dir, "reports"))
                from . import graphutil
                m["graph"] = graphutil.ApkGraphEngine(
                    os.path.join(self.work_dir, "reports"))
                from . import deepdive
                m["deepdive"] = deepdive.DeepDiveEngine(
                    os.path.join(self.work_dir, "reports"))
        except Exception:
            pass
        return m

    # ------------------------------------------------------------------ api
    def handle(self, text: str, user: str = "cli") -> tuple[str, core.Job | None]:
        """Parse one command, ACK immediately. Returns (reply, accepted job)."""
        parts = (text or "").strip().split()
        if not parts or parts[0] not in (
                "/apk", "/map", "/find", "/xref", "/callers", "/callees",
                "/claims", "/why", "/plan", "/capabilities", "/analyze", "/dex",
                "/smali", "/base", "/hash", "/dexcheck", "/dexrepair", "/status",
                "/jobs", "/sessions", "/deepdive", "/investigate", "/report",
                "/cancel", "/help", "/start"):
            return HELP, None
        cmd = parts[0]

        if cmd in ("/help", "/start"):
            return HELP, None

        # ---- synchronous utility commands (fast; no heavy work) ---------
        if cmd == "/map":
            return self._map(parts[1:])
        if cmd == "/find":
            return self._find(parts[1:])
        if cmd == "/xref":
            return self._xref(parts[1:])
        if cmd == "/callers":
            return self._callers(parts[1:])
        if cmd == "/callees":
            return self._callees(parts[1:])
        if cmd == "/claims":
            return self._claims(parts[1:])
        if cmd == "/why":
            return self._why(parts[1:])
        if cmd == "/plan":
            return self._plan(parts[1:])
        if cmd == "/capabilities":
            return self._capabilities(parts[1:])
        if cmd == "/smali":
            return self._smali(parts[1:])
        if cmd == "/base":
            return self._base(parts[1:])
        if cmd == "/hash":
            return self._hash(parts[1:])
        if cmd == "/dexcheck":
            return self._dexcheck(parts[1:])
        if cmd == "/dexrepair":
            return self._dexrepair(parts[1:])

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

        if cmd == "/apk":
            return self._apk(parts[1:], user)

        if cmd == "/dex":
            return self._dex(parts[1:], user)

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

        if cmd == "/investigate":
            return self._investigate(parts[1:])

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

    def _budget_params(self, parts: list[str]) -> dict:
        """Parse --max-wall / --max-calls / --max-depth / --stall-* into the
        job params that JobManager feeds to router.budget_from_params."""
        p: dict = {}
        for flag, key, cast in (
            ("--max-wall", "max_wall", float),
            ("--max-calls", "max_calls", int),
            ("--max-depth", "max_depth", int),
            ("--stall-repeats", "stall_repeats", int),
            ("--stall-window", "stall_window", float),
        ):
            v = self._arg(parts, flag)
            if v is not None:
                try:
                    p[key] = cast(v)
                except ValueError:
                    p[key] = v  # let budget_from_params surface a bad value
        return p

    # --------------------------------------------------------------- routes
    def _analyze(self, parts: list[str], user: str) -> tuple[str, core.Job | None]:
        if not parts:
            return "/analyze <path> [--engine apkmod|mock] [--fingerprints <json>]", None
        path = os.path.abspath(os.path.expanduser(parts[0]))
        if not os.path.exists(path):
            return f"error: artifact not found (refused: {os.path.basename(path)})", None
        engine = self._arg(parts, "--engine") or None
        fp = self._arg(parts, "--fingerprints")
        params = self._budget_params(parts)
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

    def _dex(self, parts: list[str], user: str) -> tuple[str, core.Job | None]:
        if not parts:
            return "/dex <path>   (DEX Mapper: class->method->call + JNI + integrity)", None
        if "dexmapper" not in self.engines:
            return ("error: DEX Mapper needs androguard "
                    "(uv pip install androguard); /smali /base /hash /dexcheck "
                    "/dexrepair still work on stdlib"), None
        path = os.path.abspath(os.path.expanduser(parts[0]))
        if not os.path.exists(path):
            return f"error: artifact not found (refused: {os.path.basename(path)})", None
        try:
            job = self.jobs.submit("dex", path, user, "dexmapper",
                                   self._budget_params(parts))
        except (KeyError, FileNotFoundError, RuntimeError) as e:
            return f"error: {e}", None
        return (f"ACK {job.id}  engine=dexmapper\n"
                f"  queued — /status {job.id}  /cancel {job.id}"), job

    def _apk(self, parts: list[str], user: str) -> tuple[str, core.Job | None]:
        if not parts:
            return ("/apk <path>   (APK overview + Vibe IR entity graph; "
                    "then /map --sha <…>)"), None
        if "graph" not in self.engines:
            return ("error: Vibe IR needs androguard "
                    "(uv pip install androguard); /smali /base /hash /dexcheck "
                    "/dexrepair still work on stdlib"), None
        path = os.path.abspath(os.path.expanduser(parts[0]))
        if not os.path.exists(path):
            return f"error: artifact not found (refused: {os.path.basename(path)})", None
        try:
            job = self.jobs.submit("apk", path, user, "graph",
                                   self._budget_params(parts))
        except (KeyError, FileNotFoundError, RuntimeError) as e:
            return f"error: {e}", None
        return (f"ACK {job.id}  engine=graph\n"
                f"  queued — /status {job.id}  /cancel {job.id}"), job

    def _map(self, parts: list[str]) -> tuple[str, None]:
        from . import graphutil
        sha = self._arg(parts, "--sha")
        if not sha:
            if parts and not parts[0].startswith("--"):
                path = os.path.abspath(os.path.expanduser(parts[0]))
                if not os.path.exists(path):
                    return f"error: artifact not found (refused: {os.path.basename(path)})", None
                sha = core._sha256(path)
            else:
                return "/map <path>|--sha <sha256[:16]>   (Vibe IR graph + cross-layer paths)", None
        if not SHA_RE.match(sha.lower()):
            return "/map <path>|--sha <sha256[:16]> (hex, 8..64 chars)", None
        sess = self.sessions.load(sha)
        if not sess:
            return f"no session for {sha[:8]}… — run /apk <path> first", None
        graph = (sess.get("structural") or {}).get("graph")
        if not graph:
            return (f"session {sha[:8]}… has no Vibe IR graph layer yet "
                    f"(engines: {', '.join(sess.get('engines', []) or ['?'])}) — run /apk <path>"), None
        return graphutil.render_map(graph, sha), None

    def _find(self, parts: list[str]) -> tuple[str, None]:
        from . import graphutil
        sha = self._arg(parts, "--sha")
        # query = every token that isn't a flag or the --sha value
        skip = set()
        for i, p in enumerate(parts):
            if p == "--sha":
                skip.update({i, i + 1})
            elif p.startswith("--"):
                skip.add(i)
        query = " ".join(p for i, p in enumerate(parts) if i not in skip).strip()
        if not query:
            return ("/find <text> --sha <sha256[:16]>   (TargetFinder over the Vibe IR: "
                    "strings, resources, classes, methods, components — run /apk <path> first)"), None
        if not sha:
            last = self._last_job_sha()
            hint = last[:16] if last else "<sha from /apk>"
            return ("no --sha: run /apk <path> first, then /find <text> --sha "
                    f"{hint}"), None
        if not SHA_RE.match(sha.lower()):
            return "/find <text> --sha <sha256[:16]> (hex, 8..64 chars)", None
        sess = self.sessions.load(sha)
        if not sess:
            return f"no session for {sha[:8]}… — run /apk <path> first", None
        graph = (sess.get("structural") or {}).get("graph")
        if not graph:
            return (f"session {sha[:8]}… has no Vibe IR graph layer yet — run /apk <path>"), None
        targets = graphutil.find_targets(graph, query)
        return graphutil.render_find(targets, query, sha), None

    def _xref_common(self, parts: list[str], mode: str, usage: str):
        from . import graphutil
        sha = self._arg(parts, "--sha")
        skip = set()
        for i, p in enumerate(parts):
            if p == "--sha":
                skip.update({i, i + 1})
            elif p.startswith("--"):
                skip.add(i)
        target = " ".join(p for i, p in enumerate(parts) if i not in skip).strip()
        if not target:
            return usage, None
        if not sha:
            last = self._last_job_sha()
            hint = last[:16] if last else "<sha from /apk>"
            return (f"no --sha: run /apk <path> first, then {usage.split()[0]} "
                    f"<M-id|Class.method> --sha {hint}"), None
        if not SHA_RE.match(sha.lower()):
            return usage + "   (hex sha, 8..64 chars)", None
        sess = self.sessions.load(sha)
        if not sess:
            return f"no session for {sha[:8]}… — run /apk <path> first", None
        graph = (sess.get("structural") or {}).get("graph")
        if not graph:
            return (f"session {sha[:8]}… has no Vibe IR graph layer yet — run /apk <path>"), None
        x = graphutil.xrefs(graph, target)
        return graphutil.render_xref(x, mode, sha), None

    def _xref(self, parts: list[str]) -> tuple[str, None]:
        return self._xref_common(parts, "xref",
                                 "/xref <M-id|Class.method> --sha <…>")

    def _callers(self, parts: list[str]) -> tuple[str, None]:
        return self._xref_common(parts, "callers",
                                 "/callers <M-id|Class.method> --sha <…>")

    def _callees(self, parts: list[str]) -> tuple[str, None]:
        return self._xref_common(parts, "callees",
                                 "/callees <M-id|Class.method> --sha <…>")

    def _last_job_sha(self) -> str | None:
        j = self._last_job_id()
        if not j:
            return None
        job = self.jobs.get(j)
        return (job.result.intake.get("sha256") if job and job.result else None)

    def _claims(self, parts: list[str]) -> tuple[str, None]:
        from . import claims as cmod
        sha = self._arg(parts, "--sha")
        if not sha:
            last = self._last_job_sha()
            if not last:
                return "run /apk <path> first, then /claims --sha <…>", None
            sha = last
        if not SHA_RE.match(sha.lower()):
            return "/claims --sha <sha256[:16]>", None
        sess = self.sessions.load(sha)
        cl = (sess or {}).get("structural", {}).get("claims")
        if not cl:
            return (f"session {sha[:8]}… has no claim set yet — run /apk <path>"), None
        return cmod.render_claims(cl, sha), None

    def _why(self, parts: list[str]) -> tuple[str, None]:
        from . import claims as cmod
        if not parts:
            return "/why <C-id> --sha <…>   (CodeTransparent trace for a claim)", None
        claim_id = parts[0]
        sha = self._arg(parts, "--sha")
        if not sha:
            last = self._last_job_sha()
            if not last:
                return "/why <C-id> --sha <…>", None
            sha = last
        if not SHA_RE.match(sha.lower()):
            return "/why <C-id> --sha <sha256[:16]>", None
        sess = self.sessions.load(sha)
        cl = (sess or {}).get("structural", {}).get("claims")
        if not cl:
            return (f"session {sha[:8]}… has no claim set yet — run /apk <path>"), None
        return cmod.why(cl, claim_id, sha), None

    def _plan(self, parts: list[str]) -> tuple[str, None]:
        from . import router
        if not parts:
            goals = ", ".join(sorted(router.METHOD_CATALOG))
            return (f"/plan <goal>   (cheapest-capable method plan)\n"
                    f"  goals: {goals}"), None
        goal = parts[0].lower()
        if goal not in router.METHOD_CATALOG:
            goals = ", ".join(sorted(router.METHOD_CATALOG))
            return f"unknown goal '{goal}'. Goals: {goals}", None
        p = router.plan(goal)
        lines = [f"PLAN '{goal}'   (cheapest-capable; live providers)",
                 f"  >> {p['summary']}"]
        if p["available"]:
            lines.append("  available:")
            for r in p["available"]:
                lines.append(f"    [{r['evidence']}/{r['cost']}] {r['method']}"
                             f"  value={r['value']}  — {r['note']}")
        if p["unavailable"]:
            lines.append("  unavailable (honest — install to enable):")
            for r in p["unavailable"]:
                lines.append(f"    [{r['evidence']}/{r['cost']}] {r['method']}"
                             f"  — {r['note']}")
        lines.append("  budget: every job is capped (wall≤300s default, "
                     "stall-detected) — /status shows it")
        return "\n".join(lines), None

    def _capabilities(self, parts: list[str]) -> tuple[str, None]:
        from . import router
        provs = router.detect_providers()
        lines = ["CAPABILITIES on this host   (live detection)"]
        for name, ok in provs.items():
            note = router.PROVIDER_NOTES.get(name, "")
            lines.append(f"  [{'x' if ok else ' '}] {name:<12} {note}")
        lines.append("\n  only available providers are used; missing ones "
                     "degrade honestly (never faked).")
        return "\n".join(lines), None

    # ------------------------------------------------- P2 utility handlers
    def _smali(self, parts: list[str]) -> tuple[str, None]:
        from . import smali
        if not parts:
            return ("/smali <name|0x..|substr> — query the Dalvik opcode "
                    f"table ({smali.opcode_count()} opcodes). "
                    "Examples: /smali invoke-virtual  /smali const  /smali 0x1a  /smali invoke"), None
        q = parts[0]
        # exact name
        if q in smali.NAME_TO_OPCODE:
            code = smali.NAME_TO_OPCODE[q]
            r = smali.query(q)
            row = r[0]
            return (f"{row['name']}  0x{row['code']:02x}  fmt={row['format']}\n  {row['desc']}\n"
                    f"  {smali.opcode_count()} opcodes in reduced table"), None
        # hex code
        if q.lower().startswith("0x") or q.isdigit():
            try:
                code = int(q, 16)
            except ValueError:
                return f"error: bad hex '{q}'", None
            if code in smali.OPCODE_TABLE:
                row = smali.query(q)[0]
                return (f"{row['name']}  0x{code:02x}  fmt={row['format']}\n  {row['desc']}\n"
                        f"  {smali.opcode_count()} opcodes in reduced table"), None
            return f"error: 0x{code:02x} not in reduced opcode table", None
        # substring
        rows = smali.query(q)
        if not rows:
            return f"error: no opcode matching '{q}'", None
        lines = [f"{len(rows)} opcodes matching '{q}':"]
        for r in rows[:40]:
            lines.append(f"  {r['name']:<18} 0x{r['code']:02x}  {r['format']}")
        if len(rows) > 40:
            lines.append(f"  … {len(rows) - 40} more")
        return "\n".join(lines), None

    def _base(self, parts: list[str]) -> tuple[str, None]:
        from . import smali
        if len(parts) < 3:
            return "/base <value> <from> <to>  (bases 2..36; from/to as '10','16','2')", None
        val_s, from_s, to_s = parts[0], parts[1], parts[2]
        try:
            from_b, to_b = int(from_s), int(to_s)
        except ValueError:
            return f"error: bases must be integers, got '{from_s}'/'{to_s}'", None
        if not (2 <= from_b <= 36 and 2 <= to_b <= 36):
            return "error: bases must be 2..36", None
        try:
            n = int(val_s, from_b)
        except ValueError:
            return f"error: '{val_s}' is not a valid base-{from_b} value", None
        neg = n < 0
        out = smali.to_base(abs(n), to_b)
        return (f"{val_s} (base {from_b}) = "
                f"{'-' if neg else ''}{out} (base {to_b})", None)

    def _hash(self, parts: list[str]) -> tuple[str, None]:
        if not parts:
            return "/hash <text>  — sha256 of the text", None
        import hashlib
        text = " ".join(parts)
        return f"sha256(\"{text}\") = {hashlib.sha256(text.encode()).hexdigest()}", None

    def _dexcheck(self, parts: list[str]) -> tuple[str, None]:
        from . import dexmapper
        if not parts:
            return "/dexcheck <path>  — validate DEX header(s)", None
        path = os.path.abspath(os.path.expanduser(parts[0]))
        if not os.path.exists(path):
            return f"error: artifact not found (refused: {os.path.basename(path)})", None
        try:
            rows = dexmapper.dex_integrity(path)
        except Exception as e:
            return f"error: {e}", None
        lines = ["DEX header check:"]
        for r in rows:
            lines.append(f"  {r['dex']}  valid={r['valid']}  version={r['version'].replace(chr(0), '')!r}")
            for d in r["details"]:
                lines.append(f"      {d}")
        return "\n".join(lines), None

    def _dexrepair(self, parts: list[str]) -> tuple[str, None]:
        from . import dexmapper
        if not parts:
            return "/dexrepair <path>  — dry-run report (read-only; does not write)", None
        path = os.path.abspath(os.path.expanduser(parts[0]))
        if not os.path.exists(path):
            return f"error: artifact not found (refused: {os.path.basename(path)})", None
        try:
            rows = dexmapper.dex_repair(path)
        except Exception as e:
            return f"error: {e}", None
        lines = ["DEX repair (DRY-RUN — input not modified):"]
        for r in rows:
            rep = r["report"]
            changed = "yes" if rep["changed"] else "no"
            lines.append(f"  {r['dex']}  changed={changed}  "
                         f"version={rep['version'].replace(chr(0), '')!r}")
            if rep.get("magic_changed"):
                lines.append(f"      magic: {rep['magic_changed']}")
            if rep.get("sig_recomputed"):
                lines.append("      sha1 signature: recomputed")
            if rep.get("chk_recomputed"):
                lines.append("      adler32 checksum: recomputed")
        lines.append("  (a real /dexrepair writes the fixed bytes to a NEW file; "
                     "this tool is read-only here)")
        return "\n".join(lines), None

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
            if m.get("method"):
                loc = f"{m.get('class')}.{m.get('method')}()"
            else:
                loc = str(m.get("class") or "")
            lines.append(f"  [{m.get('via')}] {m.get('finding', '')} "
                         f"{loc} {m.get('artifact', '')} "
                         f"{m.get('detail', '')}".rstrip())
        if res["matchCount"] > 25:
            lines.append(f"  … {res['matchCount'] - 25} more")
        return "\n".join(lines), None

    def _investigate(self, parts: list[str]) -> tuple[str, core.Job | None]:
        """Orchestrated 18-stage investigation (P10). Reuses the Vibe IR +
        xref + claims + budget; runs as a bounded, cancellable job."""
        if not parts:
            return ("/investigate <path> [target]\n"
                    "  <path>:   APK (required) — builds its own Vibe IR\n"
                    "  [target]: method (M-id / Class.method) or 'apk' "
                    "(default)\n"
                    "  e.g.  /investigate app.apk M4\n"
                    "         /investigate app.apk com.x.DemoApp.onCreate"), None
        if "deepdive" not in self.engines:
            return ("error: /investigate needs androguard "
                    "(uv pip install androguard)"), None
        pos = [p for p in parts if not p.startswith("--")]
        if not pos:
            return "/investigate <path> [target]", None
        path = os.path.abspath(os.path.expanduser(pos[0]))
        if not os.path.exists(path):
            return f"error: artifact not found (refused: {os.path.basename(path)})", None
        target = " ".join(pos[1:]).strip() or "apk"
        params = {"target": target, "sha": self._arg(parts, "--sha")}
        params.update(self._budget_params(parts))
        try:
            job = self.jobs.submit("investigate", path, "cli", "deepdive", params)
        except (KeyError, FileNotFoundError, RuntimeError) as e:
            return f"error: {e}", None
        return (f"ACK {job.id}  engine=deepdive  target='{target}'\n"
                f"  18 stages running (bounded + cancellable) — "
                f"/status {job.id}  /cancel {job.id}"), job

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
        self.inbound_dir = os.path.join(gateway.work_dir, "inbound")

    def _call(self, method: str, payload: dict) -> dict:
        import json as _json
        last = None
        for attempt in range(4):
            req = self._request(method, payload)
            try:
                with urllib.request.urlopen(req, timeout=120) as r:
                    return _json.loads(r.read())
            except (urllib.error.URLError, ConnectionResetError,
                    TimeoutError, urllib.error.HTTPError) as e:
                # HTTP 4xx (bad token, bad file_id) must not be retried
                if isinstance(e, urllib.error.HTTPError) and e.code < 500 \
                        and e.code != 429:
                    body = e.read()[:300]
                    raise RuntimeError(f"{method} -> HTTP {e.code}: {body}")
                last = e
                time.sleep(2 * (attempt + 1))
        raise RuntimeError(f"telegram {method} failed after retries: {last}")

    def _request(self, method: str, payload: dict) -> urllib.request.Request:
        # binary values go as multipart; everything else form-urlencoded
        files = {k: v for k, v in payload.items()
                 if isinstance(v, (bytes, bytearray))}
        if files:
            boundary = "----vibe" + uuid.uuid4().hex
            body = b""
            for k, v in payload.items():
                if isinstance(v, (bytes, bytearray)):
                    continue
                body += (f"--{boundary}\r\nContent-Disposition: form-data; "
                         f"name={k}\r\n\r\n{v}\r\n").encode()
            for k, v in files.items():
                body += (f"--{boundary}\r\nContent-Disposition: form-data; "
                         f'name="{k}"; filename="upload"\r\n'
                         f"Content-Type: application/octet-stream\r\n\r\n").encode()
                body += v
            body += f"--{boundary}--\r\n".encode()
            return urllib.request.Request(
                self.api + "/" + method, data=body,
                headers={"Content-Type":
                         f"multipart/form-data; boundary={boundary}"})
        return urllib.request.Request(self.api + "/" + method,
                                      data=urllib.parse.urlencode(payload).encode())

    def fetch_file(self, file_id: str, filename: str) -> str:
        """Download a Telegram file (e.g. an uploaded APK) into the inbound
        dir. Sanitized name, bounded size, returns the local path."""
        os.makedirs(self.inbound_dir, exist_ok=True)
        safe = sanitize_filename(filename)
        fr = self._call("getFile", {"file_id": file_id})
        if not fr.get("ok"):
            raise RuntimeError(f"getFile failed: {fr.get('description')}")
        size = fr["result"].get("file_size", 0)
        if size > MAX_UPLOAD_BYTES:
            raise RuntimeError(f"file too large ({size} B > {MAX_UPLOAD_BYTES} bound)")
        url = "https://api.telegram.org/file/bot" + self.token + "/" + fr["result"]["file_path"]
        path = os.path.join(self.inbound_dir, safe)
        # CDN download with retry (transient resets are common)
        last = None
        for attempt in range(4):
            try:
                with urllib.request.urlopen(url, timeout=180) as r, \
                        open(path, "wb") as out:
                    while True:
                        chunk = r.read(1 << 20)
                        if not chunk:
                            break
                        out.write(chunk)
                return path
            except (urllib.error.URLError, ConnectionResetError,
                    TimeoutError) as e:
                last = e
                time.sleep(2 * (attempt + 1))
        raise RuntimeError(f"file download failed after retries: {last}")

    def _reply(self, chat_id: int, text: str) -> None:
        self._call("sendMessage", {"chat_id": chat_id, "text": text[:4000]})

    def poll_once(self, timeout_s: int = 25) -> int:
        """One getUpdates cycle. Returns number of updates handled.

        Handles text commands AND inbound documents (APK/DEX uploads):
        document is fetched (sanitized name, 200MB bound) and submitted as
        an /analyze job. ACK-first: the user gets the job id immediately,
        then the completion message — heavy work never blocks the reply.
        """
        ups = self._call("getUpdates", {
            "timeout": timeout_s, "allowed_updates": ["message"],
        }).get("result", [])
        n = 0
        for u in ups:
            msg = u.get("message") or {}
            user_id = str((msg.get("from") or {}).get("id", ""))
            chat_id = (msg.get("chat") or {}).get("id")
            text = (msg.get("text") or "").strip()
            doc = msg.get("document")
            if chat_id is None:
                continue
            if self.allowed is not None and user_id not in self.allowed:
                self._reply(chat_id, "not authorized (user not in allowlist)")
                continue
            if doc is not None:
                # inbound APK/DEX upload -> analyze job
                try:
                    path = self.fetch_file(doc["file_id"],
                                           doc.get("file_name", "upload.bin"))
                except Exception as e:  # noqa: BLE001 — report, don't crash the loop
                    self._reply(chat_id, f"could not fetch upload: {e}")
                    continue
                reply, job = self.gw.handle(f"/analyze {path}", user=f"tg:{user_id[:6]}")
                self._reply(chat_id, reply)
                n += 1
                if job is not None:
                    self._work_and_finalize(chat_id, job)
                continue
            if not text:
                continue
            reply, job = self.gw.handle(text, user=f"tg:{user_id[:6]}")
            self._reply(chat_id, reply)
            n += 1
            if job is not None:
                self._work_and_finalize(chat_id, job)
        return n

    def _work_and_finalize(self, chat_id: int, job: core.Job) -> None:
        for j in self.gw.process_pending():
            if j is job:
                self._finalize(chat_id, j)
                return
        # job still queued behind other work — pollers of later cycles pick it
        # up via /status; (v0.1: sequential queue, single operator expected)

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
