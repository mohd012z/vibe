"""vibebot.core — engine contract, Finding schema, job manager, session store,
stateful deepdive.

This is the "engine contract" milestone from the RevEngi study: it defines the
normalization boundary so specialist engines (apkmod today; DEX / native /
Flutter / YARA later) plug in without the gateway, jobs, or clients knowing
which engine produced a result. Every finding is forced through
`normalize_finding`, which stamps provenance, confidence, and a verification
block — the Vibe answer to RevEngi's opaque server-side results.

Stdlib only. No network.
"""

from __future__ import annotations

import abc
import dataclasses
import hashlib
import json
import os
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Any

FINDING_SCHEMA_VERSION = 1

# Confidence is DERIVED from evidence level, never asserted by an engine:
# presence (E1) is weak; manifest correlation (E2) is review; an application-
# owned caller (E3) is the strongest static signal — and even that is not
# execution (runtime stays UNKNOWN).
_CONFIDENCE_BY_LEVEL = {"E1": "LOW", "E2": "REVIEW", "E3": "HIGH"}

# Finding schema (v1) — the one shape every engine's output collapses to.
#
# {
#   "id":            "FND-001"
#   "engine":        "apkmod"
#   "title":         "ADMOB present"
#   "classification":"ADVERTISING"
#   "evidenceLevel": "E3"
#   "artifact":      "classes.dex"
#   "location":      {"class": "...", "method": "..."}      # where, exactly
#   "evidence":      [{"level": "E1", "artifact": "...", "detail": "..."}]
#   "confidence":    "HIGH"                                  # derived
#   "confidenceBasis":"E3 application-owned caller"
#   "alternatives":  ["no app caller (reflection/native)"]   # falsification
#   "verification":  {"runtime": "UNKNOWN", "required": "..."}
#   "provenance":    {"tool": "apkmod.py", "schemaVersion": 1}
# }


@dataclass
class EngineSpec:
    name: str
    description: str
    formats: tuple[str, ...] = ("apk",)


@dataclass
class EngineResult:
    """What an engine hands back after a full run (already raw, pre-normalize)."""
    intake: dict
    structural: dict
    findings: list[dict]
    report_md: str
    outputs: dict = field(default_factory=dict)


class Engine(abc.ABC):
    """Contract: given a Job (artifact + user), produce an EngineResult.

    Engines may call `job.progress(...)` and `job.checkpoint(...)` to report
    step state. They must be READ-ONLY with respect to the artifact (apkmod
    never modifies bytes). Engines are target-agnostic about the *caller* —
    the same engine serves CLI and Telegram.
    """

    spec: EngineSpec

    @abc.abstractmethod
    def can_run(self, artifact: str) -> bool:
        """True if this engine handles the artifact (by extension/magic)."""

    @abc.abstractmethod
    def run(self, job: "Job") -> EngineResult:
        """Run the full analysis pipeline for job.artifact."""


class Job:
    """One unit of work. State machine: QUEUED -> RUNNING -> {COMPLETED,
    CANCELLED, FAILED}. Events are progress/checkpoint records; checkpoint is
    a resumable snapshot of per-step results."""

    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"

    def __init__(self, command: str, artifact: str, engine: str, user: str = "cli",
                 params: dict | None = None):
        self.id = "VIBE-" + uuid.uuid4().hex[:4].upper()
        self.command = command
        self.artifact = artifact
        self.engine = engine
        self.user = user
        self.params = params or {}
        self.state = self.QUEUED
        self.events: deque[dict] = deque(maxlen=200)
        self.checkpoints: dict[str, Any] = {}
        self.result: EngineResult | None = None
        self.error: str | None = None
        self.created = time.time()
        self.started: float | None = None
        self.finished: float | None = None
        self._cancel = False
        self.budget: Any = None  # router.Budget, attached by JobManager._run
        self._tg_chat: int | None = None  # transport: reply completions here

    # -- reporting ----------------------------------------------------------
    def progress(self, step: str, pct: int, note: str = "") -> None:
        if self.budget is not None:
            self.budget.record_progress(step, pct, note)
        self.events.append({"ts": time.time(), "type": "progress",
                            "step": step, "pct": pct, "note": note})

    def checkpoint(self, step: str, state: Any) -> None:
        if self.budget is not None:
            self.budget.check_wall()
        self.checkpoints[step] = state
        self.events.append({"ts": time.time(), "type": "checkpoint",
                            "step": step})

    # -- control ------------------------------------------------------------
    def request_cancel(self) -> None:
        self._cancel = True

    def cancelled(self) -> bool:
        return self._cancel

    def _progress_line(self) -> str:
        """Compact one-line progress for status display."""
        steps = [e for e in self.events if e["type"] == "progress"]
        if not steps:
            return self.state
        last = steps[-1]
        done = [e["step"] for e in steps if e.get("pct") == 100]
        return f"{self.state} last={last['step']}@{last['pct']}% done={len(done)}"

    def status(self) -> dict:
        return {
            "id": self.id, "command": self.command, "engine": self.engine,
            "user": self.user, "artifact": os.path.basename(self.artifact),
            "state": self.state,
            "progress": self._progress_line(),
            "events": len(self.events),
            "error": self.error,
        }


class JobManager:
    """Sequential worker queue (v0.1). submit() returns a Job; process() runs
    every queued job to a terminal state. Sequential keeps CPU/DOM predictable
    and matches the "heavy work must not block the transport" rule: the
    transport submits and returns the job id immediately, then polls status."""

    def __init__(self, engines: dict[str, Engine], session_store: "SessionStore",
                 max_jobs: int = 16):
        self.engines = engines
        self.sessions = session_store
        self._queue: list[Job] = []
        self._jobs: dict[str, Job] = {}
        self.max_jobs = max_jobs

    def _pick_engine(self, artifact: str) -> str:
        for name, eng in self.engines.items():
            if eng.can_run(artifact):
                return name
        # default: apkmod is the general APK handler. Recognize a backup
        # suffix (.apk.bak / .dex.bak) so a renamed APK still routes to the
        # right engine instead of a bare "no engine handles" (real, 2026-10-02).
        if "apkmod" in self.engines:
            a = artifact.lower()
            base_ext = os.path.splitext(os.path.splitext(a)[0])[1]
            if a.endswith((".apk", ".dex")) or base_ext in (".apk", ".dex"):
                return "apkmod"
        raise KeyError(f"no engine handles {artifact!r}")

    def submit(self, command: str, artifact: str, user: str = "cli",
               engine: str | None = None, params: dict | None = None) -> Job:
        if not os.path.exists(artifact):
            raise FileNotFoundError(artifact)
        if len(self._queue) >= self.max_jobs:
            raise RuntimeError("job queue full")
        eng = engine or self._pick_engine(artifact)
        if eng not in self.engines:
            raise KeyError(f"unknown engine {eng!r}")
        job = Job(command, artifact, eng, user, params)
        self._queue.append(job)
        self._jobs[job.id] = job
        return job

    def process(self) -> list[Job]:
        """Run the queue (FIFO) to completion. Returns the processed jobs."""
        out = []
        while self._queue:
            job = self._queue.pop(0)
            self._run(job)
            out.append(job)
        return out

    def _run(self, job: Job) -> None:
        from . import router
        eng = self.engines[job.engine]
        job.state = Job.RUNNING
        job.started = time.time()
        job.budget = router.budget_from_params(job.params)
        try:
            job.progress("intake", 0, "starting")
            res = router.run_with_watchdog(  # type: ignore[return-value]
                lambda: eng.run(job), job.budget)
            if job.cancelled():
                job.state = Job.CANCELLED
            else:
                # persist the session (fingerprint -> structural map + findings)
                sha = res.intake.get("sha256") or _sha256(job.artifact)
                self.sessions.upsert(sha, job.engine, res)
                job.result = res
                job.state = Job.COMPLETED
        except router.BudgetExceeded as e:
            job.error = f"budget: {e.reason}"
            job.state = Job.FAILED
        except Exception as e:  # noqa: BLE001 — job boundary
            job.error = f"{type(e).__name__}: {e}"
            job.state = Job.FAILED
        finally:
            job.finished = time.time()

    # -- queries -------------------------------------------------------------
    def get(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)

    def status(self, job_id: str) -> dict:
        j = self._jobs.get(job_id)
        return j.status() if j else {"id": job_id, "state": "UNKNOWN"}

    def cancel(self, job_id: str) -> bool:
        j = self._jobs.get(job_id)
        if j and j.state in (Job.QUEUED, Job.RUNNING):
            j.request_cancel()
            return True
        return False

    def all(self) -> list[dict]:
        return [j.status() for j in self._jobs.values()]


class SessionStore:
    """Fingerprint -> session (intake + structural + findings + deepdive
    history). This is what makes /deepdive stateful: subsequent questions
    traverse this store instead of rescanning the artifact."""

    def __init__(self, root: str):
        self.root = os.path.join(root, "sessions")
        os.makedirs(self.root, exist_ok=True)

    @staticmethod
    def key(sha256: str) -> str:
        return sha256[:16]

    def path(self, sha256: str) -> str:
        return os.path.join(self.root, f"session-{self.key(sha256)}.json")

    def graph_path(self, sha256: str) -> str:
        """Stable per-artifact graph file (v0.27). One file per SHA-256,
        replaced on /apk re-runs — not the timestamped report duplicate."""
        return os.path.join(self.root, f"graph-{self.key(sha256)}.json")

    @staticmethod
    def _fingerprint(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def upsert(self, sha256: str, engine: str, res: EngineResult) -> dict:
        """Persist an engine result under the artifact's fingerprint.

        The session is the artifact's GROWING evidence graph: each engine
        (apkmod, dexmapper, graph, …) adds its own structural layer and
        findings WITHOUT clobbering the others, so /apk + /dex + /map on the
        same SHA-256 compose into one session. `engine` = last run (back-compat);
        `engines` = all engines that have contributed.
        """
        prev = self.load(sha256) or {}
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # structural: union of keys (new engine adds its layer, keeps others)
        merged_structural = dict(prev.get("structural") or {})
        merged_structural.update(res.structural or {})

        # findings: union by id (a re-run refreshes its own, keeps others')
        byid = {f["id"]: f for f in (prev.get("findings") or [])}
        for f in (res.findings or []):
            byid[f["id"]] = f

        # intake: merge, but a None in the new result must not erase a value
        # an earlier engine established (e.g. package resolved by apkmod)
        intake = dict(prev.get("intake") or {})
        for k, v in (res.intake or {}).items():
            if v is not None:
                intake[k] = v

        engines = list(prev.get("engines") or ([prev["engine"]]
                                               if prev.get("engine") else []))
        if engine and engine not in engines:
            engines.append(engine)

        # v0.27: the Vibe IR graph is the big payload (a real production APK
        # = 163MB of nodes+calls). Storing it INLINE made the session 274MB:
        # every /find//xref//deepdive loaded all of it and record_deepdive
        # re-WROTE it on each append (measured: ~6s serialize / ~1.7s parse
        # on the real F-Droid session). Now the graph lives in a stable
        # per-artifact file (graph-<sha16>.json, replaced on /apk re-runs —
        # not the timestamped report duplicate) and the session carries only
        # a fingerprinted reference. Pre-v0.27 sessions (inline graph) keep
        # working: load_graph falls back to the inline copy.
        new_graph = (res.structural or {}).get("graph")
        if isinstance(new_graph, dict) and new_graph.get("nodes") is not None:
            gp = self.graph_path(sha256)
            payload = json.dumps(new_graph, separators=(",", ":"))
            tmp = gp + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(payload)
            os.replace(tmp, gp)  # atomic on POSIX: readers never see partial
            # Store the FILE NAME, not the absolute path — the graph file sits
            # next to the session (both under <root>/sessions/), so a $ref
            # stays valid if the whole work dir is moved/renamed.
            merged_structural["graph"] = {
                "$ref": os.path.basename(gp),
                "$sha256": self._fingerprint(payload.encode("utf-8")),
            }

        data = {
            "sha256": sha256,
            "engine": engine,
            "engines": engines,
            "intake": intake,
            "structural": merged_structural,
            "findings": list(byid.values()),
            "report": (res.outputs or {}).get("report") or prev.get("report"),
            "deepdive": prev.get("deepdive", []),
            "updated": now,
            "created": prev.get("created") or now,
        }
        self.save(data)
        return data

    def load(self, sha256: str) -> dict | None:
        p = self.path(sha256)
        if not os.path.exists(p):
            return None
        return json.load(open(p, encoding="utf-8"))

    def save(self, data: dict) -> None:
        p = self.path(data["sha256"])
        tmp = p + ".tmp"
        # compact + atomic: a real session's claims/overview/falsifications are
        # ~11MB (indent=2 more than doubled it for no benefit on a
        # machine-written file); the .tmp+replace keeps readers off a half-
        # written session during the (now rare) ~11MB write.
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, separators=(",", ":"))
        os.replace(tmp, p)

    def load_graph(self, session: dict) -> dict | None:
        """Resolve a session's Vibe IR graph to the dict consumers need.

        v0.27+ sessions store ``structural.graph = {"$ref": path,
        "$sha256": …}`` (the graph lives in a stable per-artifact file);
        pre-v0.27 sessions store it INLINE (fallback). Integrity: if the
        referenced file's bytes no longer hash to ``$sha256`` (torn write /
        stale ref / tamper) it is NOT trusted silently — we return None and
        let the caller report "no graph layer" honestly.
        """
        g = (session.get("structural") or {}).get("graph")
        if not isinstance(g, dict):
            return None
        if "$ref" not in g:
            return g if g.get("nodes") is not None else None
        ref, want = g.get("$ref"), g.get("$sha256")
        if not ref:
            return None
        # $ref is a file name next to the session (portable across work-dir
        # moves); accept an absolute path too for any pre-existing session.
        path = ref if os.path.isabs(ref) else os.path.join(self.root, ref)
        if not os.path.exists(path):
            return None
        try:
            with open(path, "rb") as f:
                payload = f.read()
        except OSError:
            return None
        if want and self._fingerprint(payload) != want:
            return None  # integrity mismatch — never trust silently
        data = json.loads(payload)
        return data if isinstance(data, dict) else None

    def list(self) -> list[str]:
        return sorted(f[8:-5] for f in os.listdir(self.root)
                      if f.startswith("session-") and f.endswith(".json"))


# ------------------------------------------------------------------ findings

def confidence_for(evidence_level: str, has_callers: bool = False) -> tuple[str, str]:
    """Derive confidence from the strongest evidence level (+caller bonus)."""
    lvl = (evidence_level or "E1").upper()
    conf = _CONFIDENCE_BY_LEVEL.get(lvl, "LOW")
    basis = f"evidence level {lvl}"
    if lvl == "E3":
        basis = "application-owned caller (E3)" + (" with caller list" if has_callers else "")
    elif lvl == "E2":
        basis = "manifest correlation (E2)"
    elif lvl == "E1":
        basis = "presence only (E1)"
    return conf, basis


def normalize_finding(raw: dict, engine: str, seq: int) -> dict:
    """Force a raw engine finding into the shared Finding schema (v1).

    Engines supply semantic fields; this guarantees the invariants every
    consumer relies on: stable id, provenance, derived confidence, a location,
    and a verification block that keeps runtime honest (UNKNOWN until observed).
    """
    ev = raw.get("evidence") or []
    levels = [str(e.get("level", "E1")).upper() for e in ev]
    level = max(levels, key=lambda x: int(x[1])) if levels else "E1"
    has_callers = bool(raw.get("appCallers")) or any(
        e.get("level") == "E3" for e in ev)
    conf, basis = confidence_for(level, has_callers)

    location = {}
    for e in ev:
        if e.get("class") or e.get("method"):
            location = {"class": e.get("class"), "method": e.get("method")}
            break
    if not location:
        location = {"class": raw.get("sdk") or raw.get("title")}

    return {
        "id": raw.get("id") or f"FND-{seq:03d}",
        "engine": engine,
        "title": raw.get("title") or f"{raw.get('sdk', 'finding')} present",
        "classification": raw.get("classification", "UNKNOWN"),
        "evidenceLevel": level,
        "artifact": _first_artifact(ev) or raw.get("artifact"),
        "location": location,
        "evidence": ev,
        "callGraph": raw.get("appCallers") or None,
        "confidence": conf,
        "confidenceBasis": basis,
        "alternatives": raw.get("falsification") or raw.get("alternatives")
                        or ["none identified"],
        "verification": {
            "runtime": "UNKNOWN",
            "required": raw.get("runtimeVerify") or
                        "launch, exercise the screen, confirm in logs",
        },
        "provenance": {"tool": engine, "schemaVersion": FINDING_SCHEMA_VERSION},
    }


def _first_artifact(ev: list[dict]) -> str | None:
    for e in ev:
        if e.get("artifact"):
            return e["artifact"]
    return None


# ------------------------------------------------------------------ deepdive

def deepdive(session: dict, target: str,
             resolved_graph: dict | None = None) -> dict:
    """Traverse an EXISTING session for `target` without rescanning.

    target forms (engine-agnostic; reads whatever the engine stored):
      * a class/method name — substring match across findings + location +
        (for dexmapper) the stored call graph
      * "callers"     — every application-owned caller referenced in findings
      * "native"/"jni" — native libs (apkmod) OR JNI inventory (dexmapper)
      * "references"  — all evidence rows (class/method refs)
      * "calls"       — dexmapper: every recorded method invocation
    Returns {"target":..., "matches":[...], "traversed":N}.

    v0.27: the graph-engine graph may live OUTSIDE the session (a
    ``structural.graph = {"$ref": …, "$sha256": …}`` reference, resolved by
    ``SessionStore.load_graph``). Pass the resolved dict via `resolved_graph`;
    an INLINE graph (pre-v0.27 sessions, test fixtures) still works as before.
    """
    t = (target or "").strip().lower()
    matches: list[dict] = []
    findings = session.get("findings", [])
    structural = session.get("structural", {}) or {}
    jni = structural.get("jni", [])
    calls = structural.get("calls", [])
    # Graph-engine session shape (vibe-graph): everything lives under
    # structural.graph — nodes{method,class,native,...} + calls[] — NOT the
    # dexmapper flat structural.calls / structural.jni / structural.nativeLibs
    # (v0.26, found on the real F-Droid session: /deepdive returned 0 matches
    # for org.fdroid.MainActivity.onCreate although it was present as M-id in
    # the stored graph, because this function only read the dexmapper shape).
    # v0.27: resolved_graph (from a $ref) wins over the inline copy; a $ref
    # placeholder has no "nodes", so it is skipped, never traversed as-is.
    graph = resolved_graph
    if graph is None:
        sg = structural.get("graph")
        graph = sg if isinstance(sg, dict) and sg.get("nodes") is not None else {}
    g_nodes = graph.get("nodes", {}) if isinstance(graph.get("nodes"), dict) else {}
    g_methods = g_nodes.get("method", []) or []
    g_native = g_nodes.get("native", []) or []
    g_calls = graph.get("calls", []) or []
    g_libs = graph.get("library_files", []) or []

    if t in ("callers", "caller"):
        for f in findings:
            # apkmod exposes app-owned callers in callGraph (structured);
            # E3 evidence rows are a fallback (their class is the SDK target).
            for c in f.get("callGraph") or f.get("appCallers") or []:
                matches.append({"via": "E3 caller", "finding": f["id"],
                                "class": c.get("class"), "method": c.get("method"),
                                "detail": f"invokes {c.get('invokes', '')} "
                                          f"(in {c.get('artifact', '')})"})
            for e in f.get("evidence", []):
                if e.get("level") == "E3" and not f.get("callGraph"):
                    matches.append({"via": "E3 caller", "finding": f["id"],
                                    "class": e.get("class"), "method": e.get("method"),
                                    "detail": e.get("detail")})
        # dexmapper: callers = every call where the caller is app-owned
        for c in calls:
            matches.append({"via": "caller", "class": c.get("caller"),
                            "method": c.get("callerMethod"),
                            "detail": f"{c.get('invokeKind')} -> "
                                      f"{c.get('targetClass')}.{c.get('targetMethod')}"})
        # graph-engine: callers = every stored call edge (caller = app method)
        for c in g_calls:
            matches.append({"via": "caller", "class": c.get("caller"),
                            "method": c.get("callerMethod"),
                            "detail": f"{c.get('invokeKind')} -> "
                                      f"{c.get('targetClass')}.{c.get('targetMethod')}"})
    elif t in ("references", "reference", "refs"):
        for f in findings:
            for e in f.get("evidence", []):
                matches.append({"via": f["evidenceLevel"], "finding": f["id"],
                                "class": e.get("class"), "method": e.get("method"),
                                "artifact": e.get("artifact"),
                                "detail": e.get("detail")})
    elif t in ("native", "so", "elf", "jni"):
        for lib in structural.get("nativeLibs", []):
            matches.append({"via": "structural", "artifact": lib})
        for j in jni:
            matches.append({"via": "jni", "class": j.get("class"),
                            "method": j.get("method"), "artifact": j.get("dex"),
                            "detail": "native method (JNI entry point)"})
        # graph-engine: native methods (nodes.native) + library files
        for n in g_native:
            if not t or t in ("native", "so", "elf", "jni"):
                matches.append({"via": "jni", "class": n.get("class"),
                                "method": n.get("method"),
                                "artifact": n.get("id"),
                                "detail": "native method (JNI entry point)"})
        if not t or t in ("native", "so", "elf", "jni"):
            for lib in g_libs:
                matches.append({"via": "structural", "artifact": lib})
    elif t in ("calls", "call"):
        for c in calls:
            matches.append({"via": "call", "class": c.get("caller"),
                            "method": c.get("callerMethod"),
                            "detail": f"{c.get('invokeKind')} "
                                      f"{'{'+','.join(c.get('regs', []))+'} ' if c.get('regs') else ''}-> "
                                      f"{c.get('targetClass')}.{c.get('targetMethod')}"})
        # graph-engine: same shape, stored under structural.graph
        for c in g_calls:
            matches.append({"via": "call", "class": c.get("caller"),
                            "method": c.get("callerMethod"),
                            "detail": f"{c.get('invokeKind')} "
                                      f"{'{'+','.join(c.get('regs', []))+'} ' if c.get('regs') else ''}-> "
                                      f"{c.get('targetClass')}.{c.get('targetMethod')}"})
    else:
        # substring match over findings (sdk/title/location)
        for f in findings:
            hay = json.dumps(
                {"sdk": f.get("sdk") or f.get("title"),
                 "location": f.get("location")},
                ensure_ascii=False).lower()
            if t and t in hay:
                matches.append({"via": "substring", "finding": f["id"],
                                "location": f.get("location"),
                                "evidenceLevel": f.get("evidenceLevel")})
        # dexmapper: substring over the stored call graph (caller or target)
        for c in calls:
            hay = f"{c.get('caller','')}.{c.get('callerMethod','')} " \
                  f"{c.get('targetClass','')}.{c.get('targetMethod','')}".lower()
            if t and t in hay:
                matches.append({"via": "call", "class": c.get("caller"),
                                "method": c.get("callerMethod"),
                                "detail": f"{c.get('invokeKind')} -> "
                                          f"{c.get('targetClass')}.{c.get('targetMethod')}"})
        # dexmapper: substring over JNI inventory
        for j in jni:
            if t and t in f"{j.get('class','')}.{j.get('method','')}".lower():
                matches.append({"via": "jni", "class": j.get("class"),
                                "method": j.get("method"),
                                "detail": "native method (JNI entry point)"})
        # graph-engine: substring over stored method nodes (the primary
        # lookup — a class or Class.method name matching a real M-node)
        for m in g_methods:
            hay = f"{m.get('class','')}.{m.get('name','')}".lower()
            if t and t in hay:
                matches.append({"via": "method", "class": m.get("class"),
                                "method": m.get("name"),
                                "artifact": m.get("dex"),
                                "detail": f"{m.get('id','')} "
                                          f"native={m.get('native')}"})
        # graph-engine: substring over the stored call graph
        for c in g_calls:
            hay = f"{c.get('caller','')}.{c.get('callerMethod','')} " \
                  f"{c.get('targetClass','')}.{c.get('targetMethod','')}".lower()
            if t and t in hay:
                matches.append({"via": "call", "class": c.get("caller"),
                                "method": c.get("callerMethod"),
                                "detail": f"{c.get('invokeKind')} -> "
                                          f"{c.get('targetClass')}.{c.get('targetMethod')}"})
        # graph-engine: substring over the native (JNI) nodes
        for n in g_native:
            if t and t in f"{n.get('class','')}.{n.get('method','')}".lower():
                matches.append({"via": "jni", "class": n.get("class"),
                                "method": n.get("method"), "artifact": n.get("id"),
                                "detail": "native method (JNI entry point)"})

    if matches:
        note = "traversed stored session (no rescan)"
    elif graph:
        # graph-engine session: the graph WAS traversed — a 0 is a real
        # negative (the target is not in this artifact), not a missing scan.
        note = ("no match in the stored graph (traversed "
                f"{len(g_methods)} methods, {len(g_calls)} call edges — "
                "target not present in this artifact)")
    else:
        note = "no stored matches — run /analyze or /dex first"
    return {"target": target, "matchCount": len(matches), "matches": matches,
            "note": note}


def record_deepdive(store: SessionStore, sha256: str, target: str) -> dict:
    session = store.load(sha256)
    if not session:
        return {"error": "no session for artifact — run /analyze first"}
    # v0.27: resolve the graph if it lives in a $ref file (real production
    # sessions) so deepdive can traverse it; inline graphs pass through None.
    graph = store.load_graph(session)
    result = deepdive(session, target, resolved_graph=graph)
    session.setdefault("deepdive", []).append(
        {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
         "target": target, "matchCount": result["matchCount"]})
    store.save(session)
    return result


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def to_serializable(obj: Any) -> Any:
    """JSON-safe round trip (dataclasses / tuples)."""
    return json.loads(json.dumps(obj, default=dataclasses.asdict))
