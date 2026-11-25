"""vibebot.dex2c — DEX→C++ protection provider (v0.38).

Two faces of the dex2c method (study: studies/2026-11-25-dex2c-provider.md):

  1. RE side — `detect`: is this APK ALREADY dex2c-protected? Pure heuristics
     over zip entries + .so bytes + (optionally) native method names. Evidence
     levels, honest gaps — a missing signal is NOT OBSERVED, never absence.
       E1  a .so from the dex2c family (libnc / libdex2c / libdex2cpp) present
       E2  that .so carries the generated code's pthread_rwlock cache imports
       E3  a cluster of native methods with 100+ char JNI long names
           (needs DEX parse — androguard glue, optional)

  2. Build side — `convert` / `codegen`: APK in -> protected APK out (or
     generated C++ only). Runs OUR in-house dex2cpp driver
     (/opt/data/dex2cpp, amimo/dcc Apache-2.0 engine + NDK cross-build) as a
     SUBPROCESS — never imported (license + crash isolation, the external-tool
     invariant). Missing toolchain -> honest Dex2cError / job FAILED with
     "NOT OBSERVED (install to enable)", never a fake success.

Stdlib-only module: androguard (for the E3 DEX parse) is imported lazily and
only inside `native_long_names()`, so detection degrades E1/E2 without it.
"""
from __future__ import annotations

import importlib
import os
import re
import shutil
import subprocess
import zipfile

from . import core

# ---------------------------------------------------------------------------
# errors + toolchain seam
# ---------------------------------------------------------------------------


class Dex2cError(Exception):
    """Driver/toolchain failure with an honest, actionable message."""


_DEFAULTS = {
    "driver": "/opt/data/dex2cpp/dex2cpp.py",
    "python": "/opt/data/dex2cpp/.venv/bin/python",
    # the driver's own keystore (its signed demo key) — the protected APK is
    # re-signed, so the input app's cert is lost (same contract as /kit patch).
    "keystore": "/opt/data/dex2cpp/keystore/dex2cpp.keystore",
}


class Toolchain:
    """Resolved at CALL time (router rule) via VIBE_DEX2CPP_* env overrides."""

    def __init__(self, env: dict | None = None):
        self.env = dict(os.environ)
        if env:
            self.env.update(env)

    def _p(self, name: str) -> str:
        return self.env.get(f"VIBE_DEX2CPP_{name.upper()}", _DEFAULTS.get(name, ""))

    def driver(self) -> str:
        return self._p("driver")

    def python(self) -> str:
        return self._p("python") or shutil.which("python3") or "python3"

    def keystore(self) -> str:
        return self._p("keystore")

    def _have(self, name: str) -> str:
        p = self._p(name)
        if not p:
            return ""
        return p if os.path.exists(p) else ""

    def missing(self) -> list[str]:
        return [n for n in ("driver", "python") if not self._have(n)]

    def require(self) -> None:
        missing = self.missing()
        if missing:
            raise Dex2cError(
                "dex2cpp toolchain NOT OBSERVED on this host: "
                + ", ".join(f"{n} ({self._p(n) or '?no path?'} — set "
                            f"VIBE_DEX2CPP_{n.upper()})" for n in missing))

    def available(self) -> bool:
        return not self.missing()

    def run(self, cmd: list[str], timeout: float) -> tuple[int, str, str]:
        """One driver invocation, bounded by the job's wall budget.

        Returns (rc, stdout, stderr) — the engine parses them; a nonzero rc
        becomes a Dex2cError with the driver's tail output (evidence)."""
        if not self.available():
            self.require()
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError as e:
            raise Dex2cError(f"tool not found: {e.filename} — NOT OBSERVED") from e
        except subprocess.TimeoutExpired:
            raise Dex2cError(f"driver timed out after {timeout}s") from None
        return r.returncode, r.stdout or "", r.stderr or ""


def detect_provider() -> bool:
    """Live ground truth for router.CAPABILITIES — called at detect time."""
    return Toolchain().available()


# ---------------------------------------------------------------------------
# RE side: pure detection heuristics (unit-testable, no toolchain)
# ---------------------------------------------------------------------------

# dex2c-family .so bases: amimo/dcc ships libnc, codehasan/Anon4You ship
# libdex2c, our in-house build ships libdex2cpp.
SO_FAMILY = ("libnc", "libdex2c", "libdex2cpp")

# E2 machinery markers: a dex2c .so's generated code carries a two-level
# member-resolution cache guarded by pthread read-write locks — those libc
# IMPORTS are in .dynsym (unlike the JNI vtable calls, which are hidden
# struct-pointer calls and never appear as strings/imports). A plain hand-
# written JNI bridge does not import the rwlock pair.
MACHINERY_STRINGS = ("pthread_rwlock_rdlock", "pthread_rwlock_wrlock")

# JNI long names (Java_pkg_Class_method__desc) for a real app are 100+ chars;
# a hand-written JNI bridge rarely exceeds ~60.
LONG_JNI_MIN = 100
_JNI_NAME_RE = re.compile(r"^Java_[A-Za-z0-9_]+$")


def so_family_hits(entries: list[str]) -> list[str]:
    """E1: lib/<abi>/libnc.so / libdex2c*.so entries (zip inventory names)."""
    hits = []
    for name in entries:
        n = name.lower()
        if "/lib/" not in n and not n.startswith("lib/"):
            continue
        base = os.path.basename(n)
        if not base.endswith(".so"):
            continue
        stem = base[:-3]  # libnc / libdex2c / libdex2cpp
        if any(stem == s or stem.startswith(s) for s in SO_FAMILY):
            hits.append(name)
    return sorted(set(hits))


def strings_suggest_machinery(data: bytes,
                              min_hits: int = 2) -> list[str]:
    """E2: which cache-machinery identifiers appear in the .so bytes.

    Raw byte scan (no ELF parsing): the pthread_rwlock import names sit in
    the .dynsym string table and survive stripping. Both names = the dex2c
    two-level cache; one = coincidence, not machinery."""
    found = [s for s in MACHINERY_STRINGS if s.encode() in data]
    return found if len(found) >= min_hits else []


def long_jni_names(names: list[str], min_len: int = LONG_JNI_MIN) -> list[str]:
    """E3 (support): which names are dex2c-scale JNI long names."""
    return sorted({n for n in names
                   if len(n) >= min_len and _JNI_NAME_RE.match(n)})


def native_long_names_from_dex(path: str) -> list[str]:
    """E3: native method JNI long names from the DEX (androguard, lazy).

    Honest degrade: androguard absent -> Dex2cError, the caller marks E3
    NOT OBSERVED rather than skipping detection entirely."""
    try:
        _apk = importlib.import_module("androguard.core.bytecodes.apk")
        _dvm = importlib.import_module("androguard.core.bytecodes.dvm")
        _conf = importlib.import_module("androguard.core.androconf")
        _conf.show_logging(level=50)
    except ImportError as e:
        raise Dex2cError("androguard not installed — E3 NOT OBSERVED "
                         "(uv pip install androguard)") from e
    out: set[str] = set()
    files = [path] if (path.lower().endswith(".dex")
                       or zipfile.is_zipfile(path) and not
                       path.lower().endswith(".apk")) else []
    if not files:
        a = _apk.APK(path)
        files = a.get_all_dex()
    for x in files:
        vm = _dvm.DalvikVMFormat(x)
        for m in vm.get_methods():
            acc = m.get_access_flags()
            if acc & 0x1000:  # ACC_NATIVE
                cls, name, _desc = m.get_triple()
                if not (cls.startswith("L") and cls.endswith(";")):
                    cls = "L" + cls + ";"
                out.add("Java_" + cls[1:-1].replace("/", "_")
                        + "_" + name.replace("<", "").replace(";", ""))
    return long_jni_names(list(out))


def classify(entries: list[str], so_data: dict[str, bytes] | None = None,
             native_names: list[str] | None = None) -> dict:
    """Combine the three evidence tiers into a verdict card (pure).

    `so_data`: {zip entry name: .so bytes} for the family hits (E2 source).
    `native_names`: JNI long names to scan (E3 source) — already-parsed or
    raw; both shapes are tolerated (long_jni_names filters)."""
    so_data = so_data or {}
    hits = so_family_hits(entries)
    evidence: list[dict] = []
    for h in hits:
        evidence.append({"level": "E1", "artifact": h,
                         "detail": f"dex2c-family .so present: {h}"})
    mach: list[str] = []
    for h in hits:
        data = so_data.get(h)
        if data is None:
            continue
        f = strings_suggest_machinery(data)
        if f:
            mach = f
            evidence.append({"level": "E2", "artifact": h,
                             "detail": "generated-code cache machinery "
                                       "(pthread_rwlock pair): " + ", ".join(f)})
    if native_names:
        longs = long_jni_names(native_names)
        if longs:
            evidence.append({"level": "E3", "artifact": "(dex native decls)",
                             "detail": f"{len(longs)} native methods with "
                                       f"100+ char JNI long names"})
    protected = bool(hits) and bool(mach)
    if protected:
        verdict = ("PROTECTED — dex2c-family .so with generated-code "
                   "machinery (RegisterNatives at runtime). Smali-patching "
                   "the protected methods is impossible (no body): hook the "
                   "JNI symbols or the RegisterNatives table instead.")
    elif hits:
        verdict = ("SUSPECT — family .so present but generated-code "
                   "machinery NOT OBSERVED (hand-rolled lib, or file "
                   "unreadable); not confirmed.")
    elif longs := long_jni_names(native_names or []):
        verdict = (f"SUSPECT — {len(longs)} long JNI names but no family .so "
                   "observed (custom lib name?).")
    else:
        verdict = ("NOT dex2c-protected — no family .so, no long JNI name "
                   "cluster observed in this artifact.")
    return {"protected": protected, "evidence": evidence, "verdict": verdict,
            "soHits": hits, "machinery": mach}


def zip_detect(path: str) -> dict:
    """Stdlib detection over a real APK/zip: E1 + E2 (E3 left NOT OBSERVED
    — the caller may enrich with native_long_names_from_dex)."""
    with zipfile.ZipFile(path) as z:
        entries = z.namelist()
        hits = so_family_hits(entries)
        so_data = {h: z.read(h) for h in hits if h in entries}
    res = classify(entries, so_data)
    res["e3"] = "NOT OBSERVED (pass native method names for the DEX tier)"
    return res


# ---------------------------------------------------------------------------
# Build side: driver invocation + output parsing
# ---------------------------------------------------------------------------

_SELECT_TAIL_RE = re.compile(r"#\s*(\d+)\s+selected,\s*(\d+)\s+skipped")


def parse_select_report(stdout: str) -> dict:
    """Driver `select` stdout: one Lcom/x;name(desc) line per selected
    method + a '# N selected, M skipped' tail line."""
    lines = [l.strip() for l in stdout.splitlines() if l.strip()]
    selected = [l for l in lines if l.startswith("L")]
    m = _SELECT_TAIL_RE.search(stdout)
    n = int(m.group(1)) if m else len(selected)
    skipped = int(m.group(2)) if m else None
    return {"selected": selected, "count": n, "skipped": skipped}


def parse_convert_report(log: str) -> dict:
    """Driver `convert` stderr/stdout log -> structural summary (pure)."""
    out: dict = {}
    m = re.search(r"selected (\d+) methods \((\d+) skipped", log)
    if m:
        out["selected"] = int(m.group(1))
        out["skipped"] = int(m.group(2))
    m = re.search(r"codegen: (\d+) ok, (\d+) errors", log)
    if m:
        out["codegenOk"] = int(m.group(1))
        out["codegenErrors"] = int(m.group(2))
    m = re.search(r"smali: (\d+) methods marked native", log)
    if m:
        out["patched"] = int(m.group(1))
    for m in re.finditer(r"(arm64-v8a|armeabi-v7a|x86|x86_64)\s+"
                         r"\{[^}]*'ok':\s*(True|False)", log):
        out.setdefault("abis", {})[m.group(1)] = m.group(2) == "True"
    m = re.search(r"OUTPUT (\S+) \((\d+) bytes\)", log)
    if m:
        out["output"] = m.group(1)
        out["outSize"] = int(m.group(2))
    if "apksigner verify:" in log:
        out["signed"] = True
    return out


# ---------------------------------------------------------------------------
# job engine
# ---------------------------------------------------------------------------


class Dex2cEngine(core.Engine):
    """core.Engine adapter over the dex2cpp driver (subprocess isolation).

    params: {op: "select"|"codegen"|"convert", rules: <path to rules file>,
             abis: [...], out: <override output path>}
    READ-ONLY with respect to the artifact: the driver decodes into its own
    workdir; we only add outputs under out_dir.
    """

    spec: core.EngineSpec

    tc: Toolchain

    def __init__(self, out_dir: str, toolchain: Toolchain | None = None):
        self.out_dir = out_dir
        self.tc = toolchain or Toolchain()
        self.spec = core.EngineSpec(
            name="dex2c",
            description="DEX->C++ protection: detect dex2c .so's (RE) or "
                        "convert selected methods to native (build)",
            formats=("apk",))

    def can_run(self, artifact: str) -> bool:
        return artifact.lower().endswith(".apk")

    def run(self, job: core.Job) -> core.EngineResult:

        params = job.params or {}
        op = params.get("op", "convert")
        rules = params.get("rules")
        if not rules:
            raise Dex2cError("no --rules file (regex over Lcom/x;name(desc))")
        if not os.path.exists(rules):
            raise Dex2cError(f"rules file not found: {rules}")

        job.progress("toolchain", 5, "driver + NDK check")
        self.tc.require()
        base = os.path.basename(job.artifact).rsplit(".", 1)[0]
        os.makedirs(self.out_dir, exist_ok=True)

        abis = params.get("abis") or ["arm64-v8a", "armeabi-v7a"]
        wall = float(params.get("max_wall", 1800))
        if op == "select":
            out = os.path.join(self.out_dir, base + "-select.txt")
            cmd = [self.tc.python(), self.tc.driver(), "select",
                   job.artifact, "-f", rules]
            rc, stdout, stderr = self.tc.run(cmd, timeout=wall)
            if rc != 0:
                tail = (stderr or "").strip().splitlines()[-8:]
                raise Dex2cError(f"driver rc={rc}\n" + "\n".join(tail))
            job.progress("done", 90, "selection report")
            rep = parse_select_report(stdout)
            with open(out, "w") as fp:
                fp.write(stdout)
            md = (f"# DEX2C select\n\n"
                  f"- artifact: {os.path.basename(job.artifact)}\n"
                  f"- selected: {rep['count']}  (skipped: {rep['skipped']})\n"
                  f"- full list: {out}\n\n## selected (first 40)\n")
            md += "\n".join("  " + m for m in rep["selected"][:40])
            if len(rep["selected"]) > 40:
                md += f"\n  … {len(rep['selected']) - 40} more (in report file)"
            return core.EngineResult(
                intake={"sha256": "", "package": "", "versionName": "select"},
                structural={"op": "select", "selected": rep["count"],
                            "skipped": rep["skipped"]},
                findings=[], report_md=md,
                outputs={"report": out})
        if op == "codegen":
            out = os.path.join(self.out_dir, base + "-codegen")
            cmd = [self.tc.python(), self.tc.driver(), "codegen",
                   job.artifact, "-f", rules, "-o", out]
        else:
            out_apk = params.get("out") or os.path.join(
                self.out_dir, base + ".dex2cpp.apk")
            cmd = [self.tc.python(), self.tc.driver(), "convert",
                   job.artifact, "-f", rules, "-o", out_apk,
                   "--abis"] + abis
            if self.tc.keystore() and os.path.exists(self.tc.keystore()):
                cmd += ["--keystore", self.tc.keystore()]

        job.progress(op, 15, "select + codegen (CFG→SSA→C++)")
        job.checkpoint("plan", {"op": op, "rules": rules, "abis": abis})
        rc, stdout, stderr = self.tc.run(cmd, timeout=wall)
        log = (stderr or "") + ("\n" + stdout if stdout else "")

        if rc not in (0, 2):  # codegen rc=2 = "done with errors"
            tail = (log or "(no output)").strip().splitlines()[-8:]
            raise Dex2cError(f"driver rc={rc}\n" + "\n".join(tail))
        job.progress(op, 80, "apktool patch + NDK build + sign")

        if op == "codegen":
            ncpp = 0
            if os.path.isdir(out):
                ncpp = sum(1 for r, _d, fs in os.walk(out) for f in fs
                           if f.endswith(".cpp"))
            job.progress("done", 100, f"{ncpp} C++ files")
            md = (f"# DEX2C codegen\n\n- artifact: {os.path.basename(job.artifact)}\n"
                  f"- C++ files: {ncpp}\n- out: {out}\n")
            if rc == 2:
                md += "\n⚠ codegen finished with errors — check driver log.\n"
            return core.EngineResult(
                intake={"sha256": "", "package": "", "versionName": "codegen"},
                structural={"op": "codegen", "cppFiles": ncpp},
                findings=[], report_md=md,
                outputs={"src": out})

        rep = parse_convert_report(log)
        out_apk = rep.get("output")
        if not out_apk or not os.path.exists(out_apk):
            raise Dex2cError("driver reported no OUTPUT apk\n" + log[-800:])
        # copy into our work dir (the driver may write elsewhere)
        final = os.path.join(self.out_dir,
                             os.path.basename(out_apk))
        if os.path.abspath(out_apk) != os.path.abspath(final):
            shutil.copy2(out_apk, final)
        findings = [core.normalize_finding({
            "id": "D2C-001", "sdk": "DEX2CPP",
            "classification": "NATIVE_PROTECTION",
            "evidence": [
                {"level": "E1", "artifact": "libdex2cpp.so",
                 "detail": f"{rep.get('selected', '?')} methods moved out of "
                           f"DEX into native"},
                {"level": "E2", "artifact": final,
                 "detail": f"protected APK signed={rep.get('signed')}, "
                           f"size={rep.get('outSize', os.path.getsize(final))} B"},
            ],
            "appCallers": [],
            "falsification": ["on-device launch + method call (needs a device)"],
        }, "dex2c", 1)]
        md = (f"# DEX2C convert\n\n"
              f"- selected: {rep.get('selected')}  (skipped: {rep.get('skipped')})\n"
              f"- codegen: {rep.get('codegenOk')} ok, {rep.get('codegenErrors')} errors\n"
              f"- smali marked native: {rep.get('patched')}\n"
              f"- abis: {rep.get('abis')}\n"
              f"- out: {final} ({rep.get('outSize')} B, signed={rep.get('signed')})\n\n"
              f"Honest limits: raises RE effort, does not hide logic (names "
              f"resurface via FindClass/RegisterNatives hooks). Runtime "
              f"verification is on-device.\n")
        job.progress("done", 100, f"out {rep.get('outSize', 0):,} B")
        return core.EngineResult(
            intake={"sha256": "", "package": "", "versionName": "dex2cpp"},
            structural={k: rep.get(k) for k in
                        ("selected", "skipped", "codegenOk", "codegenErrors",
                         "patched", "abis", "signed", "outSize")},
            findings=findings, report_md=md,
            outputs={"apk": final})
