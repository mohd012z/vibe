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
import shutil
import hashlib
import zipfile
import threading
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
  /falsify [--sha <…>]   Falsifier board: claims re-checked vs the artifact
  /why <C-id> [--sha <…>] CodeTransparent trace: claim -> evidence -> bytes
  /plan <goal>           cheapest-capable method plan (live providers)
  /capabilities          what's installed here (honest detection)
  /analyze <path> [--engine apkmod|dexmapper] [--fingerprints <json>]
  /dex <path>            DEX Mapper job: class->method->call map + JNI + integrity
  /xmatch <src.apk> <dst.apk>  cross-version method match (job) — carry validated findings
  /native <path>         Radare native provider: ELF fns/imports/exports + JNI bridge
  /harness <srcdir>      native-harness validation: build + run C test under qemu (E5)
  /kmeta <dex|apk> [f]   recover original (pre-R8) Kotlin names from @Metadata (E2)
  /commands [query]      searchable command registry (L0 always · L1 on demand)
  /oracle <target> [mode] Frida oracle GATE (dry-run — is a runtime call allowed? E5)
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
    def __init__(self, work_dir: str, engines_map: dict[str, core.Engine] | None = None,
                 file_root: str | None = None):
        self.work_dir = work_dir
        os.makedirs(work_dir, exist_ok=True)
        # opt-in path containment (GHIDRA_MCP_FILE_ROOT pattern, lupoxyz #6):
        # set via file_root= or VIBE_FILE_ROOT. Unset -> no gating (unchanged).
        self.file_root = file_root or os.environ.get("VIBE_FILE_ROOT") or None
        self.sessions = core.SessionStore(work_dir)
        self.engines = engines_map or self._default_engines()
        self.jobs = core.JobManager(self.engines, self.sessions)
        # v0.30: one-shot disclosure set by _artifact() when a .apks bundle was
        # unpacked for this call; appended to the ACK/reply, then cleared.
        self._bundle_note = ""

    def _containment_err(self, path: str) -> str | None:
        """Error string if `path` is outside the active file root, else None.
        Enforced ONLY when file_root is set — the containment gate is opt-in so
        unset deployments keep their current (no-gate) behavior."""
        if not self.file_root:
            return None
        root = os.path.realpath(self.file_root)
        p = os.path.realpath(path)
        if p != root and not p.startswith(root + os.sep):
            return (f"error: {os.path.basename(path)} is outside the file root "
                    f"(VIBE_FILE_ROOT) — path-accepting commands are "
                    f"containment-gated (NOT OBSERVED outside the root)")
        return None

    # v0.30: bound on unpacking an .apks bundle's base.apk (safety; the upload
    # is already bounded by MAX_UPLOAD_BYTES, extraction is ~1:1 with zip size)
    _BUNDLE_MAX_EXTRACT = 512 * 1024 * 1024

    def _apks_base(self, apks_path: str) -> tuple[str, str, str | None]:
        """v0.30: unpack an .apks bundle (Android App Bundle / ApkSet).

        An .apks is a ZIP containing base.apk (all DEX + manifest) plus
        split_config.*.apk (per-ABI / per-language / per-density resources and
        native libs). We extract base.apk into a per-bundle cache dir and
        analyze THAT; the splits are disclosed as NOT analyzed (honest).

        Returns (base_apk_path, disclosure_note, error).
        """
        try:
            with zipfile.ZipFile(apks_path) as z:
                names = z.namelist()
                if "base.apk" not in names:
                    return "", "", "error: .apks has no base.apk (not a valid ApkSet)"
                info = z.getinfo("base.apk")
                if info.is_dir():
                    return "", "", "error: .apks 'base.apk' is a directory (corrupt bundle)"
                if info.file_size > self._BUNDLE_MAX_EXTRACT:
                    return "", "", (f"error: base.apk too large to unpack "
                                    f"({info.file_size} B > {self._BUNDLE_MAX_EXTRACT})")
                # per-bundle cache key: sha256 of the bundle itself
                sha = hashlib.sha256()
                with open(apks_path, "rb") as f:
                    while True:
                        chunk = f.read(1 << 20)
                        if not chunk:
                            break
                        sha.update(chunk)
                base = os.path.join(self.work_dir, "apks", sha.hexdigest()[:16],
                                    "base.apk")
                if not os.path.exists(base):
                    os.makedirs(os.path.dirname(base), exist_ok=True)
                    # single KNOWN member ('base.apk', exact name) — no
                    # arbitrary-name extraction, so no zip-slip surface
                    with z.open("base.apk") as src, open(base + ".part", "wb") as out:
                        shutil.copyfileobj(src, out, 1 << 20)
                    os.replace(base + ".part", base)
                splits = [n for n in names if n != "base.apk" and not n.endswith("/")]
                parts = []
                for n in sorted(splits):
                    sz = z.getinfo(n).file_size
                    parts.append(f"{n} ({sz / 1e6:.2f} MB)" if sz >= 1 << 20
                                 else f"{n} ({sz / 1024:.0f} KB)")
                note = (f"⚠ .apks bundle — analyzed base.apk "
                        f"({info.file_size / 1e6:.2f} MB); splits NOT analyzed: "
                        + ", ".join(parts)) if parts else \
                       (f"⚠ .apks bundle — analyzed base.apk "
                        f"({info.file_size / 1e6:.2f} MB)")
                return base, note, None
        except (zipfile.BadZipFile, OSError) as e:
            return "", "", f"error: could not unpack .apks bundle ({type(e).__name__}: {e})"

    def _artifact(self, raw: str, label: str = "artifact",
                  allow_bundle: bool = True) -> tuple[str, str | None]:
        """Resolve a user-supplied path: expand+abs, containment-gate, exist.
        Returns (abs_path, error) — error is a ready-to-return message or None.
        v0.30: a .apks bundle is unpacked to its base.apk (cached per bundle);
        the split APKs are disclosed via _bundle_note, never silently dropped."""
        path = os.path.abspath(os.path.expanduser(raw))
        ce = self._containment_err(path)
        if ce:
            return path, ce
        if not os.path.exists(path):
            return path, f"error: {label} not found (refused: {os.path.basename(path)})"
        if path.lower().endswith(".apks"):
            if not allow_bundle:
                return path, (f"error: {label} is an .apks bundle — this command "
                              f"needs a raw file/dir, not a bundle")
            base, note, err = self._apks_base(path)
            if err:
                return path, err
            self._bundle_note = note
            return base, None
        return path, None

    def _default_engines(self) -> dict[str, core.Engine]:
        m = {"apkmod": engines.ApkModEngine(os.path.join(self.work_dir, "reports")),
             "mock": engines.MockEngine()}
        # stdlib-only engines (no androguard needed): native-harness validation
        try:
            from . import harness
            m["harness"] = harness.HarnessEngine(
                os.path.join(self.work_dir, "reports"))
        except Exception:
            pass
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
                from . import native
                m["native"] = native.NativeEngine(
                    os.path.join(self.work_dir, "reports"))
                from . import xmatch
                m["xmatch"] = xmatch.XmatchEngine(
                    os.path.join(self.work_dir, "reports"))
                from . import kotlinmeta
                m["kotlinmeta"] = kotlinmeta.KotlinMetaEngine(
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
                "/claims", "/falsify", "/why", "/plan", "/capabilities",
                "/analyze", "/dex", "/xmatch",
                "/native", "/harness",
                "/kmeta",
                "/smali", "/base", "/hash", "/dexcheck", "/dexrepair", "/status",
                "/jobs", "/sessions", "/deepdive", "/investigate", "/report",
                "/cancel", "/help", "/start", "/commands", "/oracle"):
            return HELP, None
        cmd = parts[0]

        if cmd in ("/help", "/start"):
            return HELP, None

        if cmd == "/commands":
            from . import registry
            query = " ".join(parts[1:]).strip()
            return registry.render(query), None

        if cmd == "/oracle":
            from . import oracle
            # /oracle <target> [call-only|differential] [reference]
            # READ-ONLY: reports the GATING decision. It never calls the target.
            if len(parts) < 2:
                return ("/oracle <target> [call-only|differential] [reference]\n"
                        "  report whether a Frida oracle call is gated (off by\n"
                        "  default; named-exports only; no raw addresses) — dry\n"
                        "  run, does NOT call anything"), None
            tgt = parts[1]
            mode = (parts[2] if len(parts) > 2 and parts[2] in
                    (oracle.MODE_CALL_ONLY, oracle.MODE_DIFFERENTIAL)
                    else oracle.MODE_CALL_ONLY)
            ref = parts[3] if (mode == oracle.MODE_DIFFERENTIAL and len(parts) > 3) \
                else None
            d = oracle.decide(tgt, mode, reference=ref)
            on = oracle.oracle_enabled()
            lines = [f"ORACLE GATE  target='{tgt}'  mode={mode}  "
                     f"target_class={d['target_class']}"]
            lines.append(f"  oracle flag: {'ON' if on else 'OFF (default)'} "
                         f"({oracle.ENV_ORACLE_CALL})")
            lines.append(f"  decision: {'ALLOWED' if d['allowed'] else 'REFUSED'}")
            lines.append(f"  reason:   {d['reason']}")
            if not d["allowed"]:
                lines.append("  (NOT OBSERVED — nothing was called; this is a "
                             "dry-run decision report)")
            return "\n".join(lines), None

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
        if cmd == "/falsify":
            return self._falsify(parts[1:])
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

        if cmd == "/xmatch":
            return self._xmatch(parts[1:], user)

        if cmd == "/native":
            return self._native(parts[1:], user)

        if cmd == "/harness":
            return self._harness(parts[1:], user)

        if cmd == "/kmeta":
            return self._kmeta(parts[1:], user)

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
    def _bundle_ack(self, reply: str) -> str:
        """v0.30: append the .apks split-disclosure to a reply, then clear it.
        No-op if no bundle was unpacked this call (plain APKs/DEX unaffected)."""
        if self._bundle_note:
            note = self._bundle_note
            self._bundle_note = ""
            return f"{reply}\n  {note}"
        return reply

    def _analyze(self, parts: list[str], user: str) -> tuple[str, core.Job | None]:
        if not parts:
            return "/analyze <path> [--engine apkmod|mock] [--fingerprints <json>]", None
        path, err = self._artifact(parts[0])
        if err:
            return err, None
        engine = self._arg(parts, "--engine") or None
        fp = self._arg(parts, "--fingerprints")
        params = self._budget_params(parts)
        if fp:
            fp_path, fp_err = self._artifact(fp, "fingerprints file")
            if fp_err:
                return fp_err, None
            params["fingerprints"] = fp_path
        try:
            job = self.jobs.submit("analyze", path, user, engine, params)
        except KeyError as e:
            return f"error: {e}", None
        except (FileNotFoundError, RuntimeError) as e:
            return f"error: {e}", None
        return self._bundle_ack(f"ACK {job.id}  engine={job.engine}\n"
                f"  queued — /status {job.id}  /cancel {job.id}"), job
    def _dex(self, parts: list[str], user: str) -> tuple[str, core.Job | None]:
        if not parts:
            return "/dex <path>   (DEX Mapper: class->method->call + JNI + integrity)", None
        if "dexmapper" not in self.engines:
            return ("error: DEX Mapper needs androguard "
                    "(uv pip install androguard); /smali /base /hash /dexcheck "
                    "/dexrepair still work on stdlib"), None
        path, err = self._artifact(parts[0])
        if err:
            return err, None
        try:
            job = self.jobs.submit("dex", path, user, "dexmapper",
                                   self._budget_params(parts))
        except (KeyError, FileNotFoundError, RuntimeError) as e:
            return f"error: {e}", None
        return self._bundle_ack(f"ACK {job.id}  engine=dexmapper\n"
                f"  queued — /status {job.id}  /cancel {job.id}"), job
    def _xmatch(self, parts: list[str], user: str) -> tuple[str, core.Job | None]:
        """Cross-version method match: /xmatch <src.apk> <dst.apk>."""
        if not parts:
            return ("/xmatch <src.apk> <dst.apk>   match methods between two "
                    "builds (findings validated on src carried to dst as "
                    "candidates — only EXACT may skip re-validation)"), None
        if "xmatch" not in self.engines:
            return ("error: cross-version match needs androguard "
                    "(uv pip install androguard)"), None
        src, err = self._artifact(parts[0], "src artifact")
        if err:
            return err, None
        # dst = 2nd positional, or --dst <path>
        dst_raw = (parts[1] if len(parts) > 1 and not parts[1].startswith("--")
                   else self._arg(parts, "--dst"))
        if not dst_raw:
            return "/xmatch <src.apk> <dst.apk>", None
        dst, err = self._artifact(dst_raw, "dst artifact")
        if err:
            return err, None
        params = self._budget_params(parts)
        params["dst"] = dst
        try:
            job = self.jobs.submit("xmatch", src, user, "xmatch", params)
        except (KeyError, FileNotFoundError, RuntimeError) as e:
            return f"error: {e}", None
        return self._bundle_ack(f"ACK {job.id}  engine=xmatch\n"
                f"  src={os.path.basename(src)}  dst={os.path.basename(dst)}\n"
                f"  queued — /status {job.id}  /report --sha <…>  /cancel {job.id}"), job
    def _native(self, parts: list[str], user: str) -> tuple[str, core.Job | None]:
        if not parts:
            return ("/native <path>   (Radare native provider: ELF functions/"
                    "imports/exports + LocationResolver + JNI bridge; "
                    "path = .so or .apk)"), None
        if "native" not in self.engines:
            return ("error: native provider needs androguard (uv pip install "
                    "androguard); degrades to 'not installed' if radare2 is "
                    "also absent"), None
        path, err = self._artifact(parts[0])
        if err:
            return err, None
        try:
            job = self.jobs.submit("native", path, user, "native",
                                   self._budget_params(parts))
        except (KeyError, FileNotFoundError, RuntimeError) as e:
            return f"error: {e}", None
        return self._bundle_ack(f"ACK {job.id}  engine=native\n"
                f"  queued — /status {job.id}  /cancel {job.id}"), job
    def _harness(self, parts: list[str], user: str) -> tuple[str, core.Job | None]:
        if not parts:
            return ("/harness <srcdir>   (native-harness validation: build the "
                    "C/asm test harness for an ARM64 change + run it under "
                    "qemu-aarch64 — proves the change BEHAVES, E5)"), None
        if "harness" not in self.engines:
            return ("error: harness engine not registered (stdlib-only; "
                    "should always be available)"), None
        path, err = self._artifact(parts[0], "source dir", allow_bundle=False)
        if err:
            return err, None
        try:
            job = self.jobs.submit("harness", path, user, "harness",
                                   self._budget_params(parts))
        except (KeyError, FileNotFoundError, RuntimeError) as e:
            return f"error: {e}", None
        return self._bundle_ack(f"ACK {job.id}  engine=harness\n"
                f"  queued (build + qemu run) — /status {job.id}  "
                f"/cancel {job.id}"), job
    def _kmeta(self, parts: list[str], user: str) -> tuple[str, core.Job | None]:
        """Kotlin @Metadata name recovery: /kmeta <dex|apk> [class_filter]."""
        if not parts:
            return ("/kmeta <classes.dex|app.apk> [class_filter]   "
                    "recover original (pre-R8) Kotlin names from "
                    "@Metadata (E2; JVM oracle cross-check when a toolchain "
                    "is present)"), None
        if "kotlinmeta" not in self.engines:
            return ("error: @Metadata recovery needs androguard "
                    "(uv pip install androguard)"), None
        path, err = self._artifact(parts[0])
        if err:
            return err, None
        flt = (parts[1] if len(parts) > 1 and not parts[1].startswith("--")
               else None)
        params = self._budget_params(parts)
        if flt:
            params["class_filter"] = flt
        try:
            job = self.jobs.submit("kmeta", path, user, "kotlinmeta", params)
        except (KeyError, FileNotFoundError, RuntimeError) as e:
            return f"error: {e}", None
        return self._bundle_ack(f"ACK {job.id}  engine=kotlinmeta\n"
                f"  {os.path.basename(path)}  filter={flt or '(all)'}\n"
                f"  /report {job.id}   /status {job.id}"), job
    def _apk(self, parts: list[str], user: str) -> tuple[str, core.Job | None]:
        if not parts:
            return ("/apk <path|bundle.apks>   (APK overview + Vibe IR entity graph; "
                    ".apks bundle = base.apk analyzed, splits disclosed) "), None
        if "graph" not in self.engines:
            return ("error: Vibe IR needs androguard "
                    "(uv pip install androguard); /smali /base /hash /dexcheck "
                    "/dexrepair still work on stdlib"), None
        path, err = self._artifact(parts[0])
        if err:
            return err, None
        try:
            job = self.jobs.submit("apk", path, user, "graph",
                                   self._budget_params(parts))
        except (KeyError, FileNotFoundError, RuntimeError) as e:
            return f"error: {e}", None
        return self._bundle_ack(f"ACK {job.id}  engine=graph\n"
                f"  queued — /status {job.id}  /cancel {job.id}"), job
    def _session_graph(self, sha: str):
        """(session, resolved graph or None) for a stored session.

        v0.27: the graph-engine graph may live OUTSIDE the session (a
        ``structural.graph = {"$ref": …, "$sha256": …}`` reference → stable
        per-artifact file, integrity-checked by the store). Returns the
        resolved dict; a $ref that fails the integrity check / is missing
        returns (session, None) so callers report "no graph layer" honestly
        rather than trusting stale bytes.
        """
        sess = self.sessions.load(sha)
        if not sess:
            return None, None
        g = self.sessions.load_graph(sess)
        return sess, g

    def _map(self, parts: list[str]) -> tuple[str, None]:
        from . import graphutil
        sha = self._arg(parts, "--sha")
        if not sha:
            if parts and not parts[0].startswith("--"):
                path = os.path.abspath(os.path.expanduser(parts[0]))
                ce = self._containment_err(path)
                if ce:
                    return ce, None
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
        graph = self.sessions.load_graph(sess)  # v0.27: resolves $ref or inline
        if not graph:
            return (f"session {sha[:8]}… has no Vibe IR graph layer yet "
                    f"(engines: {', '.join(sess.get('engines', []) or ['?'])}) — run /apk <path>"), None
        return graphutil.render_map(graph, sha), None

    def _session_ref(self, parts: list[str]):
        """Resolve --session VIBE-XXXX / --sha <hex> to a sha. Returns
        (sha, error, consumed_flag). Neither given -> (None, None, False)."""
        jobref = self._arg(parts, "--session")
        sha = self._arg(parts, "--sha")
        if jobref:
            ref = jobref.strip().upper()
            if not ref.startswith("VIBE-"):
                return None, "--session expects a job id like VIBE-EFCB", True
            job = self.jobs.get(ref)
            if job is None:
                return None, f"no such job {ref} — check /jobs", True
            if job.result is None:
                # still queued/running (or failed) — tell the user honestly
                if job.state in ("queued", "running"):
                    return (None,
                            f"{ref} is still {job.state} — wait for its "
                            "COMPLETE message, then /find <text> --session "
                            f"{ref}", True)
                return (None, f"{ref} did not produce a session "
                        f"(state={job.state})", True)
            return job.result.intake.get("sha256"), None, True
        if sha:
            return sha, None, True
        return None, None, False

    def _find(self, parts: list[str]) -> tuple[str, None]:
        from . import graphutil
        # query = every token that isn't a flag or a flag's value
        skip = set()
        for i, p in enumerate(parts):
            if p in ("--sha", "--session"):
                skip.update({i, i + 1})
            elif p.startswith("--"):
                skip.add(i)
        query = " ".join(p for i, p in enumerate(parts) if i not in skip).strip()
        if not query:
            return ("/find <text> [--session VIBE-XXXX | --sha <sha256[:16]>]   "
                    "(TargetFinder over the Vibe IR: strings, resources, classes, "
                    "methods, components — run /apk <path> first)"), None
        sha, sess_err, have_ref = self._session_ref(parts)
        if sess_err:
            return sess_err, None
        if have_ref and not sha:
            return "that job has no session sha yet — run /apk <path> first", None
        if not have_ref:
            last = self._last_job_sha()
            hint = last[:16] if last else "<sha from /apk>"
            return ("no --sha / --session: run /apk <path> first, then "
                    f"/find <text> --session <VIBE-XXXX>  (or --sha {hint})"), None
        if not SHA_RE.match(sha.lower()):
            return "/find <text> --session VIBE-XXXX | --sha <sha256[:16]>  (hex, 8..64)", None
        sess = self.sessions.load(sha)
        if not sess:
            return f"no session for {sha[:8]}… — run /apk <path> first", None
        graph = self.sessions.load_graph(sess)  # v0.27: resolves $ref or inline
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
        graph = self.sessions.load_graph(sess)  # v0.27: resolves $ref or inline
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
        out = cmod.render_claims(cl, sha)
        board = (sess or {}).get("structural", {}).get("falsification_board")
        if board:
            out += "\n\n" + board
        return out, None

    def _falsify(self, parts: list[str]) -> tuple[str, None]:
        """The FALSIFIER board — every contradiction found re-checking the
        claims against an independent reading of the graph."""
        from . import falsify as fmod
        sha = self._arg(parts, "--sha")
        if not sha:
            last = self._last_job_sha()
            if not last:
                return "run /apk <path> first, then /falsify --sha <…>", None
            sha = last
        if not SHA_RE.match(sha.lower()):
            return "/falsify --sha <sha256[:16]>", None
        sess = self.sessions.load(sha) or {}
        st = sess.get("structural", {})
        finds = st.get("falsifications")
        if finds is None:
            # no stored findings (pre-P11 session) — run live over the graph
            g = self.sessions.load_graph(sess)  # v0.27: resolves $ref or inline
            cl = st.get("claims")
            if not g or cl is None:
                return (f"session {sha[:8]}… has no graph yet — run /apk <path>"), None
            finds = fmod.falsify_graph(g) + fmod.falsify_claims(cl, g)
        return fmod.render_falsifications(finds, sha), None

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
        path, err = self._artifact(parts[0], allow_bundle=False)
        if err:
            return err, None
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
        path, err = self._artifact(parts[0], allow_bundle=False)
        if err:
            return err, None
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
        path, err = self._artifact(pos[0])
        if err:
            return err, None
        target = " ".join(pos[1:]).strip() or "apk"
        params = {"target": target, "sha": self._arg(parts, "--sha")}
        params.update(self._budget_params(parts))
        try:
            job = self.jobs.submit("investigate", path, "cli", "deepdive", params)
        except (KeyError, FileNotFoundError, RuntimeError) as e:
            return f"error: {e}", None
        return self._bundle_ack(f"ACK {job.id}  engine=deepdive  target='{target}'\n"
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
                 allowed_user_ids: set[str] | None = None,
                 worker: bool = False):
        self.gw = gateway
        self.token = token
        self.allowed = allowed_user_ids
        self.api = f"https://api.telegram.org/bot{token}"
        self.inbound_dir = os.path.join(gateway.work_dir, "inbound")
        # worker=True (production --serve): jobs run in a background thread so
        # a heavy analysis (e.g. a 51s graph build) never blocks the poll loop.
        # worker=False (CLI/tests, back-compat): the old synchronous behavior.
        self.worker = worker
        self._wq_thread: threading.Thread | None = None
        if worker:
            # production: start the worker immediately so it's ready to drain
            # the moment a job is submitted (lazy start is a source of races)
            self._ensure_worker()

    def _ensure_worker(self) -> None:
        """Start the single background job worker if not already running."""
        if self._wq_thread is None or not self._wq_thread.is_alive():
            t = threading.Thread(target=self._worker_loop,
                                 name="vibe-job-worker", daemon=True)
            t.start()
            self._wq_thread = t

    def _has_queued(self) -> bool:
        return any(j.get("state") in (core.Job.QUEUED, core.Job.RUNNING)
                   for j in self.gw.jobs.all())

    def _worker_loop(self) -> None:
        """Background worker: drain the job queue and send each completion.

        Runs OFF the poll thread — this is the freeze fix. Only one worker
        thread exists, so process_pending() (which drains the whole queue,
        sequential) is never called concurrently. The poll thread only ever
        SUBMITS jobs (GIL-atomic list append), so no lock is needed.
        """
        while True:
            if self._has_queued():
                ran = self.gw.process_pending()
                for j in ran:
                    chat = getattr(j, "_tg_chat", None)
                    if chat is None:
                        continue  # not a telegram-originated job
                    try:
                        self._finalize(chat, j)
                    except Exception:  # noqa: BLE001 — never kill the worker
                        pass
            else:
                time.sleep(0.3)

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
        job._tg_chat = chat_id  # worker replies the completion to this chat
        if self.worker:
            # Background path (production): the poll loop returns immediately;
            # the single worker thread drains the queue and sends each
            # completion. A heavy job can no longer freeze the bot.
            self._ensure_worker()
            return
        # Synchronous path (CLI/tests, back-compat): run here as before.
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
