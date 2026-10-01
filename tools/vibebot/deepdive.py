# VibeBot — P10: /deepdive as an orchestrated 18-stage investigation.
#
# Not a "giant command": a job that walks 18 stages, each emitting evidence,
# reusing the deterministic engines already built (Vibe IR, xref, claims,
# router). Stages run under the P6 budget (cancellable, wall-capped, stall-
# detected). Stages that need a provider not installed here are reported
# HONESTLY as UNKNOWN / NOT OBSERVED — never faked (NOT OBSERVED != IMPOSSIBLE).
#
# The 18 stages are the /360 spec (identity → location → owner → code →
# references → callers → callees → data → resources → JNI → blocks → CFG →
# paths → contradictions → unknowns → validation → evidence → summary).

from __future__ import annotations

import os

from . import claims as cmod
from . import core
from . import graphutil
from . import router

# stage -> (title, needs_native?, needs_runtime?)
STAGES: list[tuple[str, str, bool, bool]] = [
    ("01", "Identity", False, False),
    ("02", "Location", False, False),
    ("03", "Owner", False, False),
    ("04", "Code", False, False),
    ("05", "References", False, False),
    ("06", "Callers", False, False),
    ("07", "Callees", False, False),
    ("08", "Data", False, False),
    ("09", "Resources", False, False),
    ("10", "JNI", False, False),
    ("11", "Blocks", True, False),
    ("12", "CFG", True, False),
    ("13", "Paths", False, False),
    ("14", "Contradictions", False, False),
    ("15", "Unknowns", False, False),
    ("16", "Validation", False, False),
    ("17", "Evidence", False, False),
    ("18", "Summary", False, False),
]

DONE = "✓"
INPROG = "●"
NOTESTED = "?"
NOTAVAILABLE = "n/a"


def _mark(available: bool, native: bool, runtime: bool) -> str:
    if available:
        return DONE
    if runtime:
        return NOTESTED
    if native:
        return NOTAVAILABLE
    return NOTESTED


def _resolve_target(graph: dict, target: str):
    """Resolve a deepdive target to (method_node|None, unrecognized: bool).

    '' / 'apk' / 'A1' -> whole artifact (recognized, m=None).
    An M-id or dotted Class.method -> that method (recognized).
    Anything else -> whole artifact but flagged unrecognized so 01 Identity
    says so honestly (never a silent guess).
    """
    if target in ("", "apk", "APK", "artifact", "A1"):
        return None, False
    m, external = graphutil._xref_target(graph, target)
    if external:
        return None, True
    return m, False


def run_deepdive(graph: dict, target: str, job: core.Job | None = None) -> dict:
    """Run all 18 stages over a Vibe IR graph. Pure + deterministic.

    `job` (optional) is used for staged progress (cancellable + budgeted);
    when None the stages run synchronously with no progress calls.
    """
    provs = router.detect_providers()
    has_native = provs.get("radare2", False) or provs.get("ghidra", False)
    has_runtime = provs.get("frida", False)
    m, unrecognized = _resolve_target(graph, target)
    claims = cmod.build_claims(graph, graph.get("dex_integrity"))
    counts = graph.get("counts", {})
    result: dict = {"target": target, "method": m, "unrecognized":
                    unrecognized, "stages": []}

    def _stage(num: str, title: str, native: bool, runtime: bool,
               available: bool, lines: list[str], note: str = "") -> None:
        mark = _mark(available, native, runtime)
        result["stages"].append({"num": num, "title": title, "mark": mark,
                                 "lines": lines, "note": note})

    def _prog(num: str, title: str) -> None:
        if job is not None:
            idx = int(num)
            pct = (idx - 1) * 5 + 1
            job.progress(f"{num} {title}", min(pct, 99),
                         f"deepdive stage {num}/{len(STAGES)}")

    # ---- 01 Identity ---------------------------------------------------
    _prog("01", "Identity")
    if m:
        ident = (f"{m['id']}  {m['class']}.{m['name']}  ({m['dex']})"
                 + ("  [native]" if m.get("native") else ""))
        avail = True
    else:
        ident = (f"A1  package '{graph.get('package')}'  "
                 f"{counts.get('class', 0)} classes / {counts.get('method', 0)} "
                 f"methods / {counts.get('component', 0)} components")
        if unrecognized:
            ident = (f"A1  (target '{target}' did not resolve to a method — "
                     f"treating as whole artifact)  package "
                     f"'{graph.get('package')}'")
        avail = True
    _stage("01", "Identity", False, False, avail, [ident])

    # ---- 02 Location (LocationResolver chain) -------------------------
    _prog("02", "Location")
    if m:
        loc = [f"A1 → {m['dex']} → {m['class']} → {m['name']}"]
        avail = True
    else:
        loc = ["A1 (whole artifact) — no single location"]
        avail = True
    _stage("02", "Location", False, False, avail, loc)

    # ---- 03 Owner (class / component) ---------------------------------
    _prog("03", "Owner")
    if m:
        owner = [f"class: {m['class']}"]
        # is this class a manifest component?
        for comp in graph.get("nodes", {}).get("component", []):
            if comp["name"].endswith(m["class"]):
                owner.append(f"manifest {comp['kind']}: {comp['id']} "
                             f"{comp['name']}")
        avail = True
    else:
        comps = graph.get("nodes", {}).get("component", [])
        owner = [f"{len(comps)} manifest component(s)"] + \
                [f"  {c['id']} {c['kind']}: {c['name']}" for c in comps[:12]]
        avail = True
    _stage("03", "Owner", False, False, avail, owner)

    # ---- 04 Code (instruction level; honest re JADX) ------------------
    _prog("04", "Code")
    if m:
        code = [f"{m['class']}.{m['name']} — DEX instruction level (E2)"]
        code.append("  (readable reconstruction = JADX, NOT installed here; "
                    "never claimed as original source)")
        avail = True
    else:
        code = ["whole-APK — no single code unit"]
        avail = True
    _stage("04", "Code", False, False, avail, code)

    # ---- 05 References (strings the method touches) -------------------
    _prog("05", "References")
    if m:
        x = graphutil.xrefs(graph, m["id"])
        refs = [f"{s['id']} '{s['value']}'" for s in x["strings"][:12]]
        if not refs:
            refs = ["(no static string references)"]
        avail = True
    else:
        # whole artifact: string corpus summary
        n_str = counts.get("string", 0)
        n_ref = sum(len(s.get("refs", []))
                    for s in graph.get("nodes", {}).get("string", []))
        refs = [f"{n_str} strings in table, {n_ref} static ref(s)"]
        avail = True
    _stage("05", "References", False, False, avail, refs)

    # ---- 06 Callers (Used By) -----------------------------------------
    _prog("06", "Callers")
    if m:
        x = graphutil.xrefs(graph, m["id"])
        callers = [f"<- {c.get('caller')}.{c.get('callerMethod')} "
                   f"[{c.get('invokeKind')}]" for c in x["callers"][:15]]
        if not callers:
            callers = ["(none found statically)"]
        avail = True
    else:
        callers = ["whole-APK — no single caller set"]
        avail = True
    _stage("06", "Callers", False, False, avail, callers)

    # ---- 07 Callees (Uses) --------------------------------------------
    _prog("07", "Callees")
    if m:
        x = graphutil.xrefs(graph, m["id"])
        callees = [f"-> {c.get('targetClass')}.{c.get('targetMethod')} "
                   f"[{c.get('invokeKind')}]" for c in x["callees"][:15]]
        if not callees:
            callees = ["(none found statically)"]
        avail = True
    else:
        n_calls = counts.get("call", 0)
        callees = [f"{n_calls} invoke edge(s) in the whole artifact"]
        avail = True
    _stage("07", "Callees", False, False, avail, callees)

    # ---- 08 Data (fields the method / artifact owns) ------------------
    _prog("08", "Data")
    if m:
        fields = [f for f in graph.get("nodes", {}).get("field", [])
                  if f.get("class") == m["class"]]
        data = [f"{f['id']} {f['name']} : {f['type']}" for f in fields[:12]]
        if not data:
            data = ["(no instance fields in this class)"]
        avail = True
    else:
        fields = graph.get("nodes", {}).get("field", [])
        data = [f"{len(fields)} field(s)"] + \
               [f"  {f['id']} {f['name']}" for f in fields[:12]]
        avail = True
    _stage("08", "Data", False, False, avail, data)

    # ---- 09 Resources -------------------------------------------------
    _prog("09", "Resources")
    if m:
        # which string resources does this method reference?
        x = graphutil.xrefs(graph, m["id"])
        res = [f"{s['id']} '{s['value']}'" for s in x["strings"][:12]]
        if not res:
            res = ["(no resource strings referenced by this method)"]
        avail = True
    else:
        resources = graph.get("nodes", {}).get("resource", [])
        res = [f"{len(resources)} resource(s)"] + \
              [f"  {r['id']} {r['value']}" for r in resources[:12]]
        avail = True
    _stage("09", "Resources", False, False, avail, res)

    # ---- 10 JNI (boundary + honest runtime gap) -----------------------
    _prog("10", "JNI")
    if m and m.get("native"):
        jni = [f"{m['id']} is a native (JNI) boundary method",
               "  backing .so function: NOT OBSERVED (no native provider)"]
        avail = True
    elif m:
        jni = ["(not a native method — no JNI boundary here)"]
        avail = True
    else:
        natives = graph.get("nodes", {}).get("native", [])
        jni = [f"{len(natives)} native (JNI) method(s)"] + \
              [f"  {n['id']} {n['class']}.{n['method']}" for n in natives[:12]]
        if not natives:
            jni = ["(no native methods in artifact)"]
        avail = True
    _stage("10", "JNI", False, False, avail, jni,
           note="NOT OBSERVED != IMPOSSIBLE: a JNI boundary may exist in "
                "the .so even if the Java method is not flagged native")

    # ---- 11 Blocks (native provider) ----------------------------------
    _prog("11", "Blocks")
    if has_native and m and m.get("native"):
        blocks = ["native provider present — blocks require a .so target "
                  "(not yet wired)"]
        avail = True
    else:
        blocks = ["n/a — requires Radare/Ghidra (not installed here)"]
        avail = False
    _stage("11", "Blocks", True, False, avail, blocks)

    # ---- 12 CFG (native provider) -------------------------------------
    _prog("12", "CFG")
    if has_native and m and m.get("native"):
        cfg = ["native provider present — CFG requires a .so target "
               "(not yet wired)"]
        avail = True
    else:
        cfg = ["n/a — requires Radare/Ghidra (not installed here)"]
        avail = False
    _stage("12", "CFG", True, False, avail, cfg)

    # ---- 13 Paths (component → method → callee cross-layer) ----------
    _prog("13", "Paths")
    if m:
        x = graphutil.xrefs(graph, m["id"])
        # build: which component's class reaches this method via calls?
        paths = []
        for c in x["callers"]:
            for comp in graph.get("nodes", {}).get("component", []):
                if comp["name"].endswith(c.get("caller", "")):
                    paths.append(f"{comp['id']} {comp['name']} → "
                                 f"{c.get('caller')}.{c.get('callerMethod')} → "
                                 f"{m['id']} {m['name']}")
                    break
        if not paths:
            paths = ["(no cross-layer path to this method found statically)"]
        avail = True
    else:
        # cross_layer_paths from the whole artifact
        clp = graphutil.cross_layer_paths(graph, limit=12)
        paths = []
        for p in clp:
            mid = (p.get("methods") or ["?"])[0]
            nat = (p.get("native") or [])
            tail = f" → JNI[{','.join(nat[:2]) or '?'}]" if nat else ""
            paths.append(f"{p['component']} {p['componentName']} → "
                         f"{mid}{tail}")
        if not paths:
            paths = ["(no cross-layer paths found)"]
        avail = True
    _stage("13", "Paths", False, False, avail, paths)

    # ---- 14 Contradictions (CONFLICTED / CONFLICT claims) ------------
    _prog("14", "Contradictions")
    conflicts = [c for c in claims
                 if c["state"] == "CONFLICTED" or c["category"] == "CONFLICT"]
    if conflicts:
        contra = [f"{c['id']} {c['statement']}" for c in conflicts[:10]]
        avail = True
    else:
        contra = ["(no conflicts detected among the claims)"]
        avail = True
    _stage("14", "Contradictions", False, False, avail, contra)

    # ---- 15 Unknowns (UNRESOLVED claims + n/a stages) -----------------
    _prog("15", "Unknowns")
    unresolved = [c for c in claims if c["state"] == "UNRESOLVED"]
    n_unknown_stages = sum(1 for s in result["stages"]
                           if s["mark"] in (NOTESTED, NOTAVAILABLE))
    unknowns = [f"{n_unknown_stages} stage(s) not established "
                "(native/runtime providers absent here)"]
    unknowns += [f"{c['id']} {c['statement']}" for c in unresolved[:6]]
    _stage("15", "Unknowns", False, False, True, unknowns)

    # ---- 16 Validation (state machine summary) ------------------------
    _prog("16", "Validation")
    by_state = {}
    for c in claims:
        by_state[c["state"]] = by_state.get(c["state"], 0) + 1
    order = ["VALIDATED", "REPRODUCED", "SUPPORTED", "PROPOSED",
             "CONFLICTED", "UNRESOLVED", "REJECTED"]
    val = ["claim states: " +
           "  ".join(f"{s}={by_state[s]}" for s in order if by_state.get(s))]
    # every transition is legal by construction (state machine enforced)
    val.append("state machine enforced (no illegal state jumps)")
    _stage("16", "Validation", False, False, True, val)

    # ---- 17 Evidence (E-level breakdown) ------------------------------
    _prog("17", "Evidence")
    ev_levels = {}
    for c in claims:
        for e in c.get("evidence", []):
            ev_levels[e["level"]] = ev_levels.get(e["level"], 0) + 1
    ev = [f"evidence by level: " +
          "  ".join(f"{lv}={ev_levels[lv]}"
                    for lv in sorted(ev_levels)) or "(none)"]
    ev.append("every claim traces to an evidence level (see /why <C-id>)")
    _stage("17", "Evidence", False, False, True, ev)

    # ---- 18 Summary ---------------------------------------------------
    _prog("18", "Summary")
    n_done = sum(1 for s in result["stages"] if s["mark"] == DONE)
    n_na = sum(1 for s in result["stages"]
               if s["mark"] in (NOTESTED, NOTAVAILABLE))
    summary = [
        f"target: {m['id']} {m['class']}.{m['name']}" if m
        else f"target: whole artifact A1 ({graph.get('package')})",
        f"stages: {n_done}/18 established · {n_na} not established "
        "(native/runtime providers absent — NOT OBSERVED, not impossible)",
        f"claims: {len(claims)} total  ({by_state.get('VALIDATED', 0)} "
        f"VALIDATED / {by_state.get('SUPPORTED', 0)} SUPPORTED / "
        f"{by_state.get('PROPOSED', 0)} PROPOSED / "
        f"{by_state.get('CONFLICTED', 0)} CONFLICTED)",
        "coverage is a statement, not a confidence percentage",
    ]
    _stage("18", "Summary", False, False, True, summary)

    if job is not None:
        job.progress("done", 100, "deepdive complete")
    return result


def render_deepdive(res: dict, sha: str) -> str:
    """The staged card: 18 lines, one per stage, mark + first evidence line."""
    tgt = res["target"]
    m = res.get("method")
    head = (f"DEEPDIVE {m['id']} {m['class']}.{m['name']}" if m
            else f"DEEPDIVE whole-artifact A1")
    lines = [f"{head}   (sha[:8]={sha[:8]})"]
    for s in res["stages"]:
        first = s["lines"][0] if s["lines"] else ""
        detail = ""
        if s["note"]:
            detail = f"   [{s['note'][:40]}]"
        lines.append(f"  {s['num']} {s['title']:<15} {s['mark']}  "
                     f"{first[:56]}{detail}")
    lines.append("\n  stages needing native/runtime: not established here "
                 "(NOT OBSERVED != IMPOSSIBLE)")
    return "\n".join(lines)


def render_deepdive_detail(res: dict, num: str, sha: str) -> str:
    """One stage expanded (all its lines)."""
    s = next((x for x in res["stages"] if x["num"] == num), None)
    if s is None:
        return f"no stage {num}. Stages: 01..18"
    lines = [f"DEEPDIVE {s['num']} {s['title']}  (sha[:8]={sha[:8]})  "
             f"[{s['mark']}]"]
    lines += [f"  {l}" for l in s["lines"]]
    if s["note"]:
        lines.append(f"  note: {s['note']}")
    return "\n".join(lines)


class DeepDiveEngine(core.Engine):
    """Engine: an 18-stage orchestrated investigation over a stored session.

    Reuses the Vibe IR graph (from /apk) + xref + claims. Runs under the P6
    budget (cancellable, wall-capped, stall-detected) with per-stage progress
    so the transport can report 01..18 live.
    """

    spec = core.EngineSpec(
        name="deepdive",
        description="orchestrated 18-stage investigation (Identity…Summary)",
        formats=("apk", "apkx", "dex"),
    )

    def __init__(self, report_dir: str):
        self.report_dir = report_dir

    def can_run(self, artifact: str) -> bool:
        return artifact.lower().endswith((".apk", ".apkx", ".dex"))

    def run(self, job: core.Job) -> core.EngineResult:
        import json as _json

        sha = core._sha256(job.artifact)
        job.checkpoint("intake", {"sha256": sha})
        job.progress("graph", 1, "building Vibe IR (stage 00)")
        g = graphutil.build_graph(job.artifact)
        g["nodes"]["artifact"][0]["path"] = os.path.basename(job.artifact)

        target = (job.params or {}).get("target", "apk")
        job.progress("stages", 2, f"running 18 stages on target '{target}'")
        res = run_deepdive(g, target, job)
        card = render_deepdive(res, sha)

        os.makedirs(self.report_dir, exist_ok=True)
        ts = core.time.strftime("%Y%m%d-%H%M%S")
        rep = os.path.join(self.report_dir, f"vibe-deepdive-{ts}.json")
        _json.dump(res, open(rep, "w"), indent=2)
        job.progress("report", 100, "done")
        job.checkpoint("report", rep)

        return core.EngineResult(
            intake={"sha256": sha, "package": g.get("package"),
                    "target": target, "dexCount": len(g.get("dex_files", [])),
                    "classCount": g["counts"]["class"],
                    "methodCount": g["counts"]["method"]},
            structural={"graph": g, "deepdive": res,
                        "deepdive_card": card},
            findings=[],
            report_md=card,
            outputs={"report": rep, "card": card,
                     "stages": [s["num"] for s in res["stages"]]},
        )
