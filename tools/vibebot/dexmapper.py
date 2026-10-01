"""vibebot.dexmapper — DEX Mapper engine: class -> method -> reference map,
JNI/native inventory, and DEX integrity. This is the static `/dex` +
`/jni_info` (+ `/dexrepair` salvage) functions of the RevEngi live menu.

Correct-by-construction: it uses androguard's OWN instruction decoder to walk
the bytecode (the same proven path tools/apkmod.py uses), NOT a hand-rolled
bit-level disassembler — the study note explicitly defers raw-hex
/asm//disasm to P3 on exactly that ground. Every reference is recorded with
its exact source class + method, so a finding is a location, not a count.

Read-only: parses only. `/dexrepair` returns repaired BYTES + a report; it
never overwrites the input (the gateway writes the copy under a new name).
"""

from __future__ import annotations

import os
import re
import sys

from . import core
from . import dexutil

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _androguard():
    try:
        import logging
        for name in ("androguard", "androguard.core", "loguru"):
            logging.getLogger(name).setLevel(logging.ERROR)
        try:
            from loguru import logger as _log
            _log.remove()
        except Exception:
            pass
        import warnings
        warnings.filterwarnings("ignore")
        from androguard.core.dex import DEX  # noqa: F401
        return True
    except ImportError:
        return False


def _dex_bytes(artifact: str) -> list[tuple[str, bytes]]:
    """Return [(name, bytes)] for every DEX in an APK, or the file itself
    if it is a bare .dex."""
    import zipfile
    if artifact.lower().endswith(".dex"):
        return [("classes.dex", open(artifact, "rb").read())]
    with zipfile.ZipFile(artifact) as z:
        names = sorted(n for n in z.namelist() if re.fullmatch(r"classes\d*\.dex", n))
        return [(n, z.read(n)) for n in names]


def map_dex(dex_bytes: bytes, dex_name: str, app_pkg: str) -> dict:
    """Build a structural map for one DEX using androguard's decoder."""
    from androguard.core.dex import DEX
    d = DEX(dex_bytes)
    classes: dict[str, dict] = {}
    calls: list[dict] = []
    for c in d.get_classes():
        cn = c.get_name().strip("L;").replace("/", ".")
        mrecs = []
        for m in c.get_methods():
            mname = m.get_name()
            acc = m.get_access_flags_string() or ""
            native = "native" in acc
            mrecs.append({"name": mname, "native": native})
            for ins in m.get_instructions():
                nm = ins.get_name() or ""
                if not nm.startswith("invoke"):
                    continue
                # androguard get_output() ~ "v1, v0, Lcls;->meth(…)V" — the
                # class reference is ALWAYS the last comma-separated piece
                # (registers come before it, method params are space-sep).
                # Same, proven approach as tools/apkmod.py detect().
                pieces = [p.strip() for p in ins.get_output().split(",")]
                tgt = pieces[-1].strip()
                regs = [p for p in pieces[:-1]
                        if re.fullmatch(r"v\d+", p) or re.fullmatch(r"\d+", p)]
                if "->" not in tgt:
                    continue
                tcls, rest = tgt.split("->", 1)
                tmeth = rest.split("(", 1)[0]
                calls.append({
                    "dex": dex_name,
                    "caller": cn,
                    "callerMethod": mname,
                    "invokeKind": nm,
                    "regs": regs,
                    "targetClass": tcls.strip("L;").replace("/", "."),
                    "targetMethod": tmeth,
                })
        classes[cn] = {"methods": mrecs,
                       "methodCount": len(mrecs),
                       "nativeCount": sum(1 for m in mrecs if m["native"])}
    return {
        "dex": dex_name,
        "classCount": len(classes),
        "callCount": len(calls),
        "classes": classes,
        "calls": calls,
        "appPackage": app_pkg,
    }


def dex_integrity(artifact: str) -> list[dict]:
    """/dexcheck: validate the DEX header of every DEX in the artifact."""
    out = []
    for name, b in _dex_bytes(artifact):
        r = dexutil.check_header(b)
        r["dex"] = name
        r["bytes"] = len(b)
        out.append(r)
    return out


def dex_repair(artifact: str) -> list[dict]:
    """/dexrepair: return repaired bytes + report per DEX (does NOT write)."""
    out = []
    for name, b in _dex_bytes(artifact):
        fixed, rep = dexutil.repair(b)
        out.append({"dex": name, "report": rep, "repaired_bytes": fixed})
    return out


def jni_inventory(artifact: str, app_pkg: str) -> list[dict]:
    """/jni_info: every native method (potential JNI entry point), with its
    class — the static half of JNI signature extraction."""
    found: list[dict] = []
    for name, b in _dex_bytes(artifact):
        m = map_dex(b, name, app_pkg)
        for cn, c in m["classes"].items():
            for meth in c["methods"]:
                if meth["native"]:
                    found.append({"dex": name, "class": cn, "method": meth["name"]})
    return found


class DexMapperEngine(core.Engine):
    """Engine: artifact -> structural DEX map + JNI findings + integrity.

    Findings (normalized, E-level E3 for app-owned callers, E1 for presence):
      * JNI-<class>  — a native method (E1: present; runtime UNKNOWN)
      * The structural map is stored in the session for /deepdive
        (targets, callers-by-class, jni).
    """

    spec = core.EngineSpec(
        name="dexmapper",
        description="DEX Mapper: class -> method -> call map, JNI/native "
                    "inventory, DEX integrity (androguard decoder)",
        formats=("apk", "dex"),
    )

    def __init__(self, report_dir: str):
        self.report_dir = report_dir

    def can_run(self, artifact: str) -> bool:
        return artifact.lower().endswith((".apk", ".dex", ".apkx"))

    def run(self, job: core.Job) -> core.EngineResult:
        if not _androguard():
            raise RuntimeError("androguard required for the DEX Mapper "
                               "(uv pip install androguard)")
        # app package: best-effort from manifest (apk) else None
        app_pkg = None
        if job.artifact.lower().endswith((".apk", ".apkx")):
            try:
                from .engines import _apkmod
                apk = _apkmod()
                inv = apk.intake(job.artifact)
                app_pkg = inv.get("package")
            except Exception:
                app_pkg = None

        job.progress("intake", 10, "reading DEX sections")
        dexes = _dex_bytes(job.artifact)
        job.checkpoint("intake", {"dexCount": len(dexes)})

        job.progress("map", 40, "class -> method -> call graph (androguard)")
        per_dex = [map_dex(b, n, app_pkg or "") for n, b in dexes]
        job.checkpoint("map", {
            "classCount": sum(m["classCount"] for m in per_dex),
            "callCount": sum(m["callCount"] for m in per_dex),
        })

        job.progress("jni", 65, "native method (JNI) inventory")
        jni = jni_inventory(job.artifact, app_pkg or "")
        job.checkpoint("jni", {"count": len(jni)})

        job.progress("integrity", 85, "DEX header validate (sha1 + adler32)")
        integrity = dex_integrity(job.artifact)
        job.checkpoint("integrity", {"ok": all(i["valid"] for i in integrity)})

        # ---- normalize to findings -------------------------------------
        raw = []
        for j in jni:
            raw.append({
                "sdk": "JNI", "title": f"native method {j['class']}.{j['method']}()",
                "classification": "NATIVE",
                "evidence": [{"level": "E1", "artifact": j["dex"],
                              "class": "L" + j["class"].replace(".", "/") + ";",
                              "method": j["method"],
                              "detail": "native method present (JNI entry point)"}],
                "falsification": ["native body is in a .so — signature is only "
                                  "the Java side; actual C impl unverified"],
            })
        findings = [core.normalize_finding(r, self.spec.name, i + 1)
                    for i, r in enumerate(raw)]

        structural = {
            "appPackage": app_pkg,
            "dexFiles": [m["dex"] for m in per_dex],
            "classCount": sum(m["classCount"] for m in per_dex),
            "methodCount": sum(m["classes"][c]["methodCount"]
                               for m in per_dex for c in m["classes"]),
            "callCount": sum(m["callCount"] for m in per_dex),
            "classes": {m["dex"]: m["classes"] for m in per_dex},
            "calls": [c for m in per_dex for c in m["calls"]],
            "jni": jni,
            "integrity": [{"dex": i["dex"], "valid": i["valid"],
                          "version": i["version"]} for i in integrity],
        }

        os.makedirs(self.report_dir, exist_ok=True)
        import json as _json
        ts = core.time.strftime("%Y%m%d-%H%M%S")
        rep = os.path.join(self.report_dir, f"dexmap-{ts}.json")
        _json.dump(structural, open(rep, "w"), indent=2)
        job.checkpoint("report", rep)
        job.progress("report", 100, "done")

        return core.EngineResult(
            intake={"sha256": core._sha256(job.artifact),
                    "package": app_pkg, "dexCount": len(dexes)},
            structural=structural,
            findings=findings,
            report_md=f"# DEX map\n\n{structural['classCount']} classes, "
                      f"{structural['callCount']} calls, {len(jni)} native.\n"
                      f"report: {rep}\n",
            outputs={"report": rep},
        )
