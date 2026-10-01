"""vibebot.graphutil — Vibe IR: a normalized, stable-ID entity graph over an
APK/DEX. This is Phase 2 of the design: every entity (artifact, component,
class, method, field, string, resource, native method) gets a deterministic
ID (A1, C3, M17, S8, R4, N2, …) assigned in sorted order, so the SAME
artifact (same SHA-256) always yields the SAME graph. That makes entity IDs
addressable — /map, /find (P3b), /xref and buttons can reference "M27" and
mean the same method on every re-run and on every client.

Built on androguard (correct-by-construction for DEX); manifest/resources
come from androguard's binary manifest parser. Read-only: parses, never
mutates the artifact.

Node ID scheme (stable per SHA-256):
  A{n} artifact          K{n} manifest component (activity/service/…)
  C{n} class             M{n} method
  F{n} field             S{n} distinct string value
  R{n} resource          N{n} native method (JNI)

Edges are NOT precomputed here (that's P3b's /xref work); the raw call list
is carried through so a renderer can compute cross-layer paths on demand.
"""

from __future__ import annotations

import re

from . import core
from . import dexmapper

GRAPH_SCHEMA = 1


def _dex_strings(d) -> dict:
    """S-node corpus + const-string refs for one DEX.

    Returns {value: {"count": int, "refs": [{class, method}], "table": [idx...]}}.
    The KEY set is the full DEX string table (every distinct value the
    bytecode can hold — type descriptors, method names, literals), which is
    the searchable corpus for /find (Phase 6 "where does this text come
    from"). ``refs`` records the const-string instructions that load it
    (the "hot" subset — where it is actually materialized into a register).
    ``count`` is the number of const-string refs (honest: a lower bound on
    total references, since type/method descriptors are referenced by
    non-const instructions we do not enumerate here).
    """
    table = list(d.get_strings())
    out: dict[str, dict] = {}
    for idx, val in enumerate(table):
        out[str(val)] = out.setdefault(str(val), {"count": 0, "refs": [], "table": []})
        out[str(val)]["table"].append(idx)
    classes = list(d.get_classes())
    for ci, c in enumerate(classes):
        cn = c.get_name().strip("L;").replace("/", ".")
        methods = list(c.get_methods())
        for mi, m in enumerate(methods):
            try:
                insns = m.get_instructions()
            except Exception:
                continue
            for ins in insns:
                if ins.get_name() not in ("const-string", "const-string/jumbo"):
                    continue
                # get_output() ~ 'vA, "value"' — the quoted tail is the string
                parts = [p.strip() for p in ins.get_output().split(",")]
                sval = None
                for p in reversed(parts):
                    if p.startswith('"') and p.endswith('"') and len(p) >= 2:
                        sval = p[1:-1]
                        break
                if sval is None:
                    continue
                e = out.setdefault(sval, {"count": 0, "refs": [], "table": []})
                e["count"] += 1
                e["refs"].append({"class": cn, "method": m.get_name()})
    return out


def build_graph(artifact: str) -> dict:
    """Build the full Vibe IR entity graph for an APK (or bare DEX).

    Returns {"schema": GRAPH_SCHEMA, "counts": {...}, "nodes": {type: [...]},
             "calls": [...]} — every node dict carries a stable "id".
    """
    dexes = dexmapper._dex_bytes(artifact)
    # ---- manifest / components (apk only) -----------------------------
    components: list[dict] = []
    package = None
    version_name = None
    version_code = None
    min_sdk = target_sdk = None
    perms: list[str] = []
    res_pkg: list[str] = []
    res_strings: list[str] = []
    if artifact.lower().endswith((".apk", ".apkx")):
        try:
            from androguard.core.apk import APK
            a = APK(artifact)
            package = a.get_package()
            version_name = a.get_androidversion_name()
            version_code = a.get_androidversion_code()
            min_sdk = a.get_min_sdk_version()
            target_sdk = a.get_target_sdk_version()
            perms = sorted(a.get_permissions() or [])
            comps = (
                [("activity", x) for x in a.get_activities()]
                + [("service", x) for x in a.get_services()]
                + [("receiver", x) for x in a.get_receivers()]
                + [("provider", x) for x in a.get_providers()])
            for kind, name in sorted(comps, key=lambda t: (t[0], t[1])):
                components.append({"kind": kind, "name": name})
            # resources: string resources (best-effort)
            try:
                res = a.get_android_resources()
                pkgs = list(res.get_res_packages().keys())
                res_pkg = [str(p) for p in pkgs]
                for p in pkgs:
                    try:
                        res_strings = sorted(res.get_res_strings(p) or [])
                    except Exception:
                        res_strings = []
            except Exception:
                pass
        except Exception:
            pass

    # ---- DEX layer ----------------------------------------------------
    classes: list[dict] = []
    methods: list[dict] = []
    fields: list[dict] = []
    natives: list[dict] = []
    calls: list[dict] = []
    str_map: dict[str, dict] = {}
    dex_names = [n for n, _ in dexes]

    for dname, db in dexes:
        from androguard.core.dex import DEX
        d = DEX(db)
        cnames = sorted(c.get_name().strip("L;").replace("/", ".")
                        for c in d.get_classes())
        # string layer per dex, merged (value -> combined refs)
        ds = _dex_strings(d)
        for v, e in ds.items():
            tgt = str_map.setdefault(v, {"count": 0, "refs": [], "table": []})
            tgt["count"] += e["count"]
            tgt["refs"].extend(e["refs"])
            tgt["table"].extend(e["table"])
        for c in d.get_classes():
            cn = c.get_name().strip("L;").replace("/", ".")
            for m in c.get_methods():
                acc = m.get_access_flags_string() or ""
                if "native" in acc:
                    natives.append({"class": cn, "method": m.get_name()})
            for f in c.get_fields():
                try:
                    fields.append({
                        "class": cn,
                        "name": f.get_name(),
                        "type": (f.get_type() or "").strip("L;").replace("/", "."),
                    })
                except Exception:
                    pass

    # dexmapper gives us the full call list + per-class method lists
    for dname, db in dexes:
        m = dexmapper.map_dex(db, dname, package or "")
        for cn, crec in m["classes"].items():
            classes.append({"dex": dname, "name": cn})
            for meth in crec["methods"]:
                methods.append({"dex": dname, "class": cn,
                                "name": meth["name"], "native": meth["native"]})
        calls.extend(m["calls"])

    # ---- assign stable IDs (sorted, deterministic) --------------------
    def _assign(nodes: list[dict], prefix: str) -> None:
        for i, n in enumerate(nodes, 1):
            n["id"] = f"{prefix}{i}"

    _assign(components, "K")
    _assign(sorted(classes, key=lambda x: (x["dex"], x["name"])), "C")
    _assign(sorted(methods, key=lambda x: (x["dex"], x["class"], x["name"])), "M")
    _assign(sorted(fields, key=lambda x: (x["class"], x["name"])), "F")
    _assign(sorted(natives, key=lambda x: (x["class"], x["method"])), "N")
    strings = []
    for i, v in enumerate(sorted(str_map), 1):
        e = str_map[v]
        strings.append({"id": f"S{i}", "value": v, "count": e["count"],
                        "refs": e["refs"]})
    resources = []
    for i, s in enumerate(res_strings, 1):
        resources.append({"id": f"R{i}", "value": s, "source": "res-string"})
    resources.append({"id": "R0", "value": "AndroidManifest.xml",
                      "source": "manifest"})

    counts = {
        "artifact": 1,
        "component": len(components),
        "class": len(classes),
        "method": len(methods),
        "field": len(fields),
        "string": len(strings),
        "resource": len(resources),
        "native": len(natives),
        "call": len(calls),
    }
    return {
        "schema": GRAPH_SCHEMA,
        "package": package,
        "version_name": version_name,
        "version_code": version_code,
        "min_sdk": min_sdk,
        "target_sdk": target_sdk,
        "permissions": perms,
        "dex_files": dex_names,
        "library_files": [],  # populated by the engine from intake
        "certificates": [],   # populated by the engine
        "counts": counts,
        "nodes": {
            "artifact": [{"id": "A1", "path": None}],  # path set by caller
            "component": components,
            "class": classes,
            "method": methods,
            "field": fields,
            "string": strings,
            "resource": resources,
            "native": natives,
        },
        "calls": calls,
    }


class ApkGraphEngine(core.Engine):
    """Engine: APK -> Vibe IR entity graph (Phase 1 overview + Phase 2 graph).

    This is the 'fast inventory before deep analysis' step: it produces the
    APK OVERVIEW card AND stores the stable-ID graph in the session so
    /map, /find (P4) and /xref (P5) can traverse it without rescanning.

    Correct-by-construction on DEX (androguard decoder); manifest/resources
    via androguard's binary manifest. Read-only.
    """

    spec = core.EngineSpec(
        name="graph",
        description="Vibe IR: APK overview + normalized entity graph "
                    "(stable A/C/M/F/S/R/N/K IDs, reproducible per SHA)",
        formats=("apk", "apkx", "dex"),
    )

    def __init__(self, report_dir: str):
        self.report_dir = report_dir

    def can_run(self, artifact: str) -> bool:
        return artifact.lower().endswith((".apk", ".apkx", ".dex"))

    def run(self, job: core.Job) -> core.EngineResult:
        import os
        import json as _json

        job.progress("intake", 10, "SHA-256 + container inventory")
        sha = core._sha256(job.artifact)
        job.checkpoint("intake", {"sha256": sha})

        job.progress("graph", 45, "building Vibe IR (manifest + DEX + strings)")
        g = build_graph(job.artifact)
        g["nodes"]["artifact"][0]["path"] = os.path.basename(job.artifact)

        # native libs + certificates (androguard)
        try:
            from androguard.core.apk import APK
            import hashlib
            a = APK(job.artifact)
            g["library_files"] = sorted(a.get_libraries() or [])
            certs = []
            for c in a.get_certificates():
                subj = ""
                try:
                    subj = c.subject.human_friendly
                except Exception:
                    pass
                certs.append({"sig": "v1", "subject": subj,
                              "sha256": c.sha256_fingerprint})
            g["certificates"] = certs
        except Exception:
            pass

        job.checkpoint("graph", g["counts"])

        # write the graph report (the evidence artifact)
        os.makedirs(self.report_dir, exist_ok=True)
        ts = core.time.strftime("%Y%m%d-%H%M%S")
        rep = os.path.join(self.report_dir, f"vibe-graph-{ts}.json")
        _json.dump(g, open(rep, "w"), indent=2)
        job.progress("report", 100, "done")
        job.checkpoint("report", rep)

        # overview findings: a few honest, evidence-anchored structural notes
        findings = []
        n_native = g["counts"]["native"]
        if g["library_files"]:
            raw = {
                "sdk": "NATIVE", "title": f"{len(g['library_files'])} native lib(s): "
                    + ", ".join(os.path.basename(x) for x in g["library_files"][:4]),
                "classification": "NATIVE",
                "evidence": [{"level": "E1", "artifact": "lib/",
                              "detail": "native libraries declared in container"}],
                "falsification": ["presence != use — a lib may be bundled unused"],
            }
            findings.append(core.normalize_finding(raw, self.spec.name, 1))
        if n_native:
            raw = {
                "sdk": "JNI", "title": f"{n_native} native (JNI) method(s)",
                "classification": "NATIVE",
                "evidence": [{"level": "E1", "artifact": "classes.dex",
                              "detail": "native methods present (JNI entry points)"}],
                "falsification": ["Java-side only; C impl in .so unverified"],
            }
            findings.append(core.normalize_finding(raw, self.spec.name, 2))

        return core.EngineResult(
            intake={"sha256": sha, "package": g.get("package"),
                    "dexCount": len(g.get("dex_files", [])),
                    "classCount": g["counts"]["class"],
                    "methodCount": g["counts"]["method"]},
            structural={"graph": g, "overview": render_overview(g, sha)},
            findings=findings,
            report_md=render_overview(g, sha) + "\n\n" + render_map(g, sha),
            outputs={"report": rep, "overview": render_overview(g, sha),
                     "map": render_map(g, sha)},
        )


def cross_layer_paths(graph: dict, limit: int = 10) -> list[dict]:
    """Component → class → method → (JNI target) paths.

    A "cross-layer path" connects a manifest-declared component to the class
    it maps to, then to the native/JNI calls that class's methods make. This
    is the Phase-3 "where does this button eventually go" primitive — here
    restricted to component→class→native (the deepest layer reachable without
    P3b's full call-chain walk).
    """
    paths: list[dict] = []
    methods = graph["nodes"]["method"]
    # class -> method ids
    by_class: dict[str, list[str]] = {}
    for m in methods:
        by_class.setdefault(m["class"], []).append(m["id"])
    # class -> native methods (from the native node list)
    class_to_native: dict[str, list[str]] = {}
    for n in graph["nodes"]["native"]:
        class_to_native.setdefault(n["class"], []).append(n["id"])
    native_classes = set(class_to_native)  # classes that HAVE native methods
    for comp in graph["nodes"]["component"]:
        cname = comp["name"]
        mids = by_class.get(cname, [])
        nat = class_to_native.get(cname, [])
        # only a call to a class that has a native method is a JNI boundary —
        # a call to e.g. android.app.Activity is a framework call, not JNI.
        called_nat = set()
        for c in graph.get("calls", []):
            if c["caller"] == cname and c["targetClass"] in native_classes:
                called_nat.add(c["targetClass"])
        if mids or nat or called_nat:
            paths.append({
                "component": comp["id"], "componentKind": comp["kind"],
                "componentName": cname,
                "methods": mids,
                "native": nat,
                "callsNativeOf": sorted(called_nat),
            })
        if len(paths) >= limit:
            break
    return paths


def render_overview(graph: dict, sha: str) -> str:
    """/apk Phase-1 card: situational awareness, not deep RE.

    Mirrors the /360 'APK OVERVIEW' block. Everything references the
    artifact by SHA-256 (immutable identity)."""
    c = graph["counts"]
    libs = graph.get("library_files") or []
    abi = sorted({lib.rsplit("/", 1)[0] for lib in libs if "/" in lib}) or ["-"]
    certs = graph.get("certificates") or []
    lines = []
    lines.append(f"APK OVERVIEW   A1 sha256[:8]={sha[:8]}")
    lines.append(f"  package        {graph.get('package') or '-'}")
    lines.append(f"  version        {graph.get('version_name')} "
                 f"(code {graph.get('version_code')})")
    lines.append(f"  min/target sdk {graph.get('min_sdk')}/{graph.get('target_sdk')}")
    lines.append(f"  DEX            {len(graph.get('dex_files', []))} "
                 f"({', '.join(graph.get('dex_files', [])) or '-'})")
    lines.append(f"  classes        {c['class']}    methods {c['method']}    "
                 f"fields {c['field']}")
    lines.append(f"  strings        {c['string']} (S-ids)   "
                 f"resources {c['resource']} (R-ids)")
    lines.append(f"  native libs    {len(libs)}   ABI {', '.join(abi)}   "
                 f"JNI methods {c['native']} (N-ids)")
    comps = graph["nodes"]["component"]
    k = {t: sum(1 for x in comps if x["kind"] == t) for t in
         ("activity", "service", "receiver", "provider")}
    lines.append(f"  components     {c['component']}  "
                 f"(act {k['activity']} / svc {k['service']} / "
                 f"rec {k['receiver']} / prov {k['provider']})")
    lines.append(f"  permissions    {len(graph.get('permissions', []))} "
                 f"({', '.join((graph.get('permissions') or [])[:4])}"
                 f"{', …' if len(graph.get('permissions', [])) > 4 else ''})")
    if certs:
        ct = certs[0]
        lines.append(f"  signature      {ct.get('sig') or 'detected'}  "
                     f"{(ct.get('subject') or '')[:40]}")
    else:
        lines.append("  signature      not extracted (certs need androguard)")
    lines.append(f"  call edges     {c['call']} (raw; /xref in P5)")
    lines.append("  Analysis       READY  [Map] [Find P4] [JNI] [Strings] [Deep Dive]")
    return "\n".join(lines)


def render_map(graph: dict, sha: str, limit: int = 10) -> str:
    """/map: tree + cross-layer paths from a stored graph."""
    c = graph["counts"]
    lines = []
    lines.append("VIBE MAP   (Vibe IR — stable entity IDs, reproducible per SHA)")
    lines.append(f"sha[:8]={sha[:8]}  schema={graph['schema']}")
    lines.append("")
    lines.append(f"A1  artifact")
    lines.append(f"     └─ manifest  package={graph.get('package')}  "
                 f"min/target sdk={graph.get('min_sdk')}/{graph.get('target_sdk')}")
    lines.append(f"     ├─ DEX   {len(graph.get('dex_files', []))} "
                 f"({', '.join(graph.get('dex_files', []))})")
    lines.append(f"     ├─ components  {c['component']} "
                 f"(K-ids)   strings {c['string']} (S-ids)   "
                 f"resources {c['resource']} (R-ids)")
    lines.append(f"     ├─ classes   {c['class']} (C-ids)")
    lines.append(f"     ├─ methods   {c['method']} (M-ids)   fields {c['field']} (F-ids)")
    lines.append(f"     ├─ native/JNI {c['native']} (N-ids)   native libs "
                 f"{len(graph.get('library_files', []))}")
    lines.append(f"     └─ call edges {c['call']} (raw; /xref resolves in P3b)")
    lines.append("")
    paths = cross_layer_paths(graph, limit=limit)
    if paths:
        lines.append(f"cross-layer paths (component → class → native):")
        for p in paths:
            m = p["methods"][:2]
            mtxt = " ".join(m) if m else "(no body in dex)"
            nat = p["native"] or (["→" + x for x in p["callsNativeOf"]][:1])
            lines.append(f"  {p['component']} {p['componentName']}")
            lines.append(f"      → methods {mtxt}{'' if m else ''}"
                         + (f"   → JNI {' '.join(nat)}" if nat else ""))
        if len(paths) >= limit:
            lines.append(f"  … (showing first {limit})")
    else:
        lines.append("cross-layer paths: (none — no component maps to a dex class "
                     "with a body, or no native/JNI edges)")
    return "\n".join(lines)
