# VibeBot — P5: pluggable Radare native provider.
#
# The last androguard-compatible piece of the design: a NATIVE provider that
# speaks through the canonical EntityResolver + LocationResolver and
# degrades HONESTLY when radare2 is not installed (this host). Key rules:
#
#   * r2 is a SUBPROCESS (never linked — JVM/tool isolation invariant).
#   * The analysis logic is separated from r2 invocation via a `RadareRunner`
#     protocol, so every parser / resolver / matcher is UNIT-TESTED with an
#     injected FakeRunner — CI runs all of it with no r2 installed.
#   * Provider-version provenance is recorded on every result (correction:
#     "tool updates -> output semantics change").
#   * JNI bridge: a Java native method whose mangled export is NOT found in
#     the .so is reported "NOT OBSERVED (export not found)" — NOT OBSERVED
#     != IMPOSSIBLE.
#   * va <-> file-offset translation is an honest approximation when the
#     target segment is unknown (reported as such).

from __future__ import annotations

import os
import re
import struct
import subprocess
import tempfile
import zipfile
from typing import Protocol

from . import core
from . import router

PROVIDER_NAME = "radare2"


class RadareLike(Protocol):
    """Anything that can run an r2 command against a file: the real
    RadareRunner (subprocess) or a test FakeRunner. This is the injection
    seam that lets every parser/resolver/matcher be unit-tested with no r2."""
    bin: str

    def version(self) -> str: ...
    def run(self, path: str, cmd: str) -> str: ...


# ------------------------------------------------------------------ runner
class ProviderUnavailable(Exception):
    """The provider binary is not installed on this host (honest degrade)."""


class ProviderError(Exception):
    """The provider ran but produced an unusable result."""


class RadareRunner:
    """Invokes r2 as a subprocess (isolation invariant: never linked).

    `r2 <path> -c '<cmd>'` ; returns stdout text. Raises
    ProviderUnavailable if r2 is missing, ProviderError on non-zero exit or
    empty output. A hard wall-clock cap (P6) applies to the subprocess.
    """

    def __init__(self, bin: str = "r2", timeout: float = 60.0):
        self.bin = bin
        self.timeout = timeout

    def _have(self) -> bool:
        return router._which(self.bin)

    def run(self, path: str, cmd: str) -> str:
        if not self._have():
            raise ProviderUnavailable(f"{self.bin} not installed on this host")
        try:
            p = subprocess.run([self.bin, path, "-c", cmd],
                               capture_output=True, text=True,
                               timeout=self.timeout)
        except FileNotFoundError:
            raise ProviderUnavailable(f"{self.bin} not installed on this host")
        except subprocess.TimeoutExpired:
            raise ProviderError(f"r2 timed out after {self.timeout}s")
        if p.returncode != 0:
            raise ProviderError(f"r2 exit {p.returncode}: {p.stderr[:200].strip()}")
        return p.stdout

    def version(self) -> str:
        try:
            out = subprocess.run([self.bin, "-v"], capture_output=True,
                                 text=True, timeout=10)
        except Exception:
            return "unknown"
        first = out.stdout.splitlines()[0] if out.stdout else "unknown"
        return first.strip()[:60]


# ------------------------------------------------------------------ ELF
def _u32(b: bytes, off: int) -> int:
    return struct.unpack_from("<I", b, off)[0]


def _u16(b: bytes, off: int) -> int:
    return struct.unpack_from("<H", b, off)[0]


def elf_segments_64(b: bytes) -> list[dict]:
    """Program headers of a 64-bit ELF -> [(p_type, p_offset, p_vaddr, p_filesz)]
    — enough to map a virtual address to a file offset. Pure."""
    if len(b) < 64 or b[:4] != b"\x7fELF":
        return []
    if b[4] != 2:  # not 64-bit
        return []
    phoff = _u32(b, 0x20)
    phentsize = _u16(b, 0x36)
    phnum = _u16(b, 0x38)
    segs = []
    for i in range(phnum):
        off = phoff + i * phentsize
        if off + 56 > len(b):
            break
        p_type = _u32(b, off)
        p_offset = struct.unpack_from("<Q", b, off + 8)[0]
        p_vaddr = struct.unpack_from("<Q", b, off + 16)[0]
        p_filesz = struct.unpack_from("<Q", b, off + 32)[0]
        segs.append({"type": p_type, "offset": p_offset, "vaddr": p_vaddr,
                     "filesz": p_filesz})
    return segs


def va_to_offset(va: int, segments: list[dict]) -> tuple[int, bool]:
    """Map a virtual address to a file offset. Returns (offset, exact).

    exact=False means the address fell in no known segment and the offset is
    an approximation (va - vaddr of the closest covering heuristic)."""
    for s in segments:
        if s["vaddr"] <= va < s["vaddr"] + s["filesz"]:
            return s["offset"] + (va - s["vaddr"]), True
    # not in any segment: approximate by subtracting the lowest vaddr
    if segments:
        base = min(s["vaddr"] for s in segments)
        return max(0, va - base), False
    return va, False


def _parse_hex_rows(out: str) -> list[str]:
    """r2 prints rows like '0x00401000  112  72  ... name'; return the rows
    that start with a hex address. Pure."""
    rows = []
    for ln in out.splitlines():
        ln = ln.strip()
        if re.match(r"^0x[0-9a-fA-F]+$", ln.split()[0] if ln.split() else ""):
            rows.append(ln)
    return rows


# ------------------------------------------------------------------ JNI
def demangle_underscore(jname: str) -> tuple[str, ...]:
    """Java `com/foo/Bar_baz` -> candidate substrings to look for in an
    export name: the underscore JNI form (`com_foo_Bar_baz`) and the
    Itanium-ish length-encoded core (`3foo3Bar4baz`). Pure."""
    if not jname:
        return ()
    pkg, _, cls_method = jname.rpartition("/")
    parts = [p for p in pkg.split("/") if p] if pkg else []
    if "." in cls_method:
        cls, _, meth = cls_method.rpartition(".")
        parts.append(cls)
        parts.append(meth)
    else:
        parts.append(cls_method)
    us = jname.replace("/", "_")
    core_enc = "".join(f"{len(p)}{p}" for p in parts)
    return (us, core_enc, jname)


def jni_export_candidates(jname: str) -> list[str]:
    """The UNIQUE candidate: the underscore JNI form (Java_com_foo_Bar_doIt
    <- com/foo/Bar_doIt). Length-encoded cores are deliberately excluded —
    a short package part (e.g. '3foo') matches too many export names and
    would produce false EXACT JNI bridges."""
    c = demangle_underscore(jname)
    return [c[0]] if c and c[0] else []


def match_jni_export(jname: str, exports: list[str]) -> str | None:
    """Find the .so export backing a Java native method (unique underscore
    form). Returns the export name or None (NOT OBSERVED)."""
    cands = jni_export_candidates(jname)
    for exp in exports:
        for c in cands:
            if c and c in exp:
                return exp
    return None


# ------------------------------------------------------------------ parse
def parse_functions(out: str) -> list[dict]:
    """r2 `aflj`-ish rows: '0xADDR  size  name' (name optional). Pure."""
    fns = []
    for row in _parse_hex_rows(out):
        toks = row.split()
        if not toks:
            continue
        va = int(toks[0], 16)
        size = int(toks[1]) if len(toks) > 1 and re.match(r"^\d+$", toks[1]) else 0
        name = toks[2] if len(toks) > 2 else f"fcn.{va:08x}"
        fns.append({"va": va, "size": size, "name": name,
                    "r2_id": f"fcn.{va:08x}"})
    return fns


def parse_exports(out: str) -> list[str]:
    """r2 `iEj`-ish rows: '0xADDR ... name'. Return names. Pure."""
    names = []
    for row in _parse_hex_rows(out):
        toks = row.split()
        if len(toks) >= 2:
            names.append(toks[-1])
    return names


def parse_imports(out: str) -> list[dict]:
    """r2 `iI` rows: 'sym:module' (one per import). Pure. A bare symbol with
    no 'sym:module' is handled (module='')."""
    imps = []
    for ln in out.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        # r2 iI: "symbol:lib.so.6" ; the symbol is everything before the last
        # colon that precedes a filename-looking module
        if ":" in ln:
            sym, _, mod = ln.rpartition(":")
            if sym and mod and (("." in mod) or mod.startswith("lib")):
                imps.append({"name": sym, "module": mod})
            else:
                imps.append({"name": ln, "module": ""})
        else:
            imps.append({"name": ln, "module": ""})
    return imps


def parse_xrefs(out: str, target_va: int) -> list[int]:
    """r2 `aXR 0xADDR`-ish rows: '0xADDR ... [ref]'. Return the FROM addresses.
    Pure."""
    froms = []
    for row in _parse_hex_rows(out):
        toks = row.split()
        if not toks:
            continue
        try:
            froms.append(int(toks[0], 16))
        except ValueError:
            continue
    return froms


# ------------------------------------------------------------------ native
def _r2_command_for(goal: str, path: str) -> str | None:
    return {
        "functions": "aflj",
        "exports": "iEj",
        "imports": "iI",
        "strings": "izj",
        "xrefs": None,  # needs a target address
    }.get(goal)


def analyze_native(path: str, runner: "RadareLike | None" = None,
                   segments: list[dict] | None = None) -> dict:
    """Run the native provider over one .so. Returns a structured result with
    location chains (va <-> file offset), imports, exports, functions, and
    provider-version provenance. Raises ProviderUnavailable / ProviderError.
    `segments` may be injected (tests); otherwise parsed from the file."""
    runner = runner or RadareRunner()
    if not os.path.exists(path):
        raise ProviderError(f"no such file: {path}")
    version = runner.version()
    try:
        raw = open(path, "rb").read()
    except OSError as e:
        raise ProviderError(f"cannot read {path}: {e}")
    if raw[:4] != b"\x7fELF":
        raise ProviderError("not an ELF file (magic mismatch)")
    if segments is None:
        segments = elf_segments_64(raw)

    fns_out = runner.run(path, "aflj")
    exps_out = runner.run(path, "iEj")
    imps_out = runner.run(path, "iI")

    fns = parse_functions(fns_out)
    exports = parse_exports(exps_out)
    imports = parse_imports(imps_out)
    # location chains: va <-> file offset (honest about approximation)
    for f in fns:
        off, exact = va_to_offset(f["va"], segments)
        f["file_offset"] = off
        f["offset_exact"] = exact
        # section name = unknown without .shstrtab parse -> mark approx
        f["section"] = ".text?"

    return {
        "provider": PROVIDER_NAME,
        "provider_version": version,
        "artifact": os.path.basename(path),
        "path": path,
        "elf_class": "64",
        "segments": segments,
        "functions": fns,
        "exports": exports,
        "imports": imports,
        "counts": {"function": len(fns), "export": len(exports),
                   "import": len(imports)},
        "provenance": {"tool": "radare2", "version": version,
                       "isolation": "subprocess", "schema": 1},
    }


def xrefs_of(native: dict, fcn_va: int, runner: "RadareLike | None" = None):
    """XREFs into a function: returns (list[from_va], segments). ProviderError
    if the provider can't answer (honest)."""
    runner = runner or RadareRunner()
    out = runner.run(native["path"], f"aXR {hex(fcn_va)}")
    return parse_xrefs(out, fcn_va), native.get("segments", [])


def resolve_native_entity(known: list[dict], provider_id: str,
                          fingerprints: dict | None = None,
                          provider: str = PROVIDER_NAME) -> dict:
    """Map a native provider entity (r2 fcn.001234 / symbol, ghidra FUN_xxx,
    a Frida runtime location) to a canonical N-id via the shared
    EntityResolver. known = [{provider, name, canonical_id, fingerprints}].
    Delegates to graphutil.resolve_entity so the SAME six states apply as for
    DEX/JADX (never merge PROBABLE as EXACT). `provider` is the provider the
    queried entity came from (default radare2)."""
    from . import graphutil
    return graphutil.resolve_entity(known, provider, provider_id,
                                    fingerprints=fingerprints)


# ------------------------------------------------------------------ JNI map
def build_jni_map(natives: list[dict], exports: list[str]) -> list[dict]:
    """Cross-layer JNI bridge: each Java native method -> .so export.

    natives = graphutil's native nodes [{id, class, method}]. A method whose
    mangled export is NOT found is NOT OBSERVED (not impossible). Pure."""
    edges = []
    for n in natives:
        jname = f"{n['class']}.{n['method']}"
        exp = match_jni_export(jname.replace(".", "/"), exports)
        edges.append({
            "java": f"{n['id']} {jname}",
            "export": exp,
            "status": "EXACT" if exp else "NOT OBSERVED",
            "note": None if exp else "export not found in module — "
                                     "NOT OBSERVED != IMPOSSIBLE",
        })
    return edges


# ------------------------------------------------------------------ render
def render_native(native: dict, limit: int = 15) -> str:
    c = native["counts"]
    lines = [f"LIB {native['artifact']}   (provider: {native['provider']} "
             f"{native['provider_version']})"]
    lines.append(f"  functions {c['function']} · exports {c['export']} · "
                 f"imports {c['import']}")
    lines.append(f"  ELF {native['elf_class']} · {len(native['segments'])} "
                 f"segment(s)")
    lines.append(f"  functions:")
    for f in native["functions"][:limit]:
        offmark = "" if f["offset_exact"] else "≈"
        lines.append(f"    {f['r2_id']}  {f['name']}  "
                     f"va=0x{f['va']:x} {f['section']} "
                     f"file=0x{f['file_offset']:x}{offmark}  ({f['size']}B)")
    if c["function"] > limit:
        lines.append(f"    … {c['function'] - limit} more")
    if native["imports"][:8]:
        lines.append(f"  imports:")
        for i in native["imports"][:8]:
            lines.append(f"    {i['name']}  ({i['module'] or '?'})")
    if native["exports"][:8]:
        lines.append(f"  exports:")
        for e in native["exports"][:8]:
            lines.append(f"    {e}")
    lines.append("  /xref <fcn> for XREFs · raw r2 only in Expert mode")
    return "\n".join(lines)


def render_jni_map(edges: list[dict]) -> str:
    lines = ["JNI BRIDGE (cross-layer: Java native -> .so export)"]
    if not edges:
        lines.append("  (no native methods declared in DEX)")
    for e in edges:
        lines.append(f"  {e['java']}  ->  {e['export'] or '—'}  [{e['status']}]")
        if e["note"]:
            lines.append(f"      {e['note']}")
    return "\n".join(lines)


# ------------------------------------------------------------------ engine
def extract_sos(apk: str) -> list[str]:
    """Extract .so files from an APK to a temp dir (read-only w.r.t. the
    APK). Returns absolute paths. arm64 preferred; all ABIs included."""
    out = []
    d = os.path.join(tempfile.mkdtemp(prefix="vibe-native-"), "libs")
    os.makedirs(d, exist_ok=True)
    with zipfile.ZipFile(apk) as z:
        names = [n for n in z.namelist() if n.endswith(".so")]
    # arm64 first, then others (deterministic order)
    def _prio(n: str) -> int:
        return 0 if "arm64" in n else 1
    names = sorted(names, key=lambda n: (_prio(n), n))
    with zipfile.ZipFile(apk) as z:
        for n in names:
            dest = os.path.join(d, os.path.basename(n))
            with z.open(n) as src, open(dest, "wb") as dst:
                dst.write(src.read())
            out.append(dest)
    return out


class NativeEngine(core.Engine):
    """Engine: native .so analysis via the pluggable Radare provider.

    Handles a direct .so (job.artifact ends in .so) or an APK (extracts its
    .so files). Degrades honestly when radare2 is absent: the job COMPLETES
    with a structural['native'] = {'provider': 'radare2', 'available': False}
    marker so the /claims + /investigate layers can report the capability
    gap — never a fabricated native analysis.
    """

    spec = core.EngineSpec(
        name="native",
        description="Radare native provider: ELF functions/imports/exports + "
                    "LocationResolver + JNI bridge (subprocess, honest degrade)",
        formats=("so", "apk", "apkx"),
    )

    def __init__(self, report_dir: str, runner: RadareRunner | None = None):
        self.report_dir = report_dir
        self.runner = runner or RadareRunner()

    def can_run(self, artifact: str) -> bool:
        return artifact.lower().endswith((".so", ".apk", ".apkx"))

    def run(self, job: core.Job) -> core.EngineResult:
        import json as _json
        from . import graphutil

        job.progress("intake", 10, "SHA-256 + native inventory")
        sha = core._sha256(job.artifact)
        job.checkpoint("intake", {"sha256": sha})

        # gather .so files (direct .so or from APK)
        if job.artifact.lower().endswith(".so"):
            sos = [job.artifact]
            apk = None
        else:
            apk = job.artifact
            sos = extract_sos(apk)

        if not sos:
            result = {"provider": PROVIDER_NAME, "available": True,
                      "libraries": [], "note": "no native libraries in artifact"}
            return self._finish(job, sha, result, apk)

        # is the provider installed?
        if not router._which(self.runner.bin):
            result = {"provider": PROVIDER_NAME, "available": False,
                      "libraries": [os.path.basename(s) for s in sos],
                      "note": f"{self.runner.bin} not installed on this host "
                              f"— native analysis NOT OBSERVED (install to enable)"}
            return self._finish(job, sha, result, apk)

        job.progress("analyze", 30, "r2: sections + functions + imports/exports")
        natives = {}
        try:
            for s in sos:
                natives[os.path.basename(s)] = analyze_native(s, self.runner)
        except (ProviderUnavailable, ProviderError) as e:
            # honest: some library could not be analyzed
            natives = {os.path.basename(s): {"provider": PROVIDER_NAME,
                                             "error": str(e)} for s in sos}
            result = {"provider": PROVIDER_NAME, "available": True,
                      "libraries": [os.path.basename(s) for s in sos],
                      "native": natives,
                      "note": f"provider error: {e}"}
            return self._finish(job, sha, result, apk)

        result = {"provider": PROVIDER_NAME, "available": True,
                  "libraries": [os.path.basename(s) for s in sos],
                  "native": natives}

        # JNI bridge: needs the DEX native decls (APK only)
        jni_map = []
        if apk:
            try:
                g = graphutil.build_graph(apk)
                jni_map = build_jni_map(
                    g["nodes"]["native"],
                    [e for n in natives.values()
                     if isinstance(n, dict) and not n.get("error")
                     for e in n.get("exports", [])])
                result["jni_map"] = jni_map
                result["native_count"] = g["counts"]["native"]
            except Exception:
                result["jni_map"] = []

        return self._finish(job, sha, result, apk)

    def _finish(self, job: core.Job, sha: str, result: dict,
                apk: str | None) -> core.EngineResult:
        import json as _json
        from . import claims as _claims
        os.makedirs(self.report_dir, exist_ok=True)
        ts = core.time.strftime("%Y%m%d-%H%M%S")
        rep = os.path.join(self.report_dir, f"vibe-native-{ts}.json")
        _json.dump(result, open(rep, "w"), indent=2)
        job.progress("report", 100, "done")
        job.checkpoint("report", rep)

        # render the card
        lines = [f"LIB NATIVE   (sha[:8]={sha[:8]})"]
        if not result.get("available"):
            lines.append(f"  {result['note']}")
        elif result.get("note") and not result.get("native"):
            lines.append(f"  {result['note']}")
        else:
            for name, nat in (result.get("native") or {}).items():
                if nat.get("error"):
                    lines.append(f"  {name}: provider error {nat['error']}")
                else:
                    lines.append(render_native(nat, limit=8))
            if "jni_map" in result:
                lines.append("")
                lines.append(render_jni_map(result["jni_map"]))
        card = "\n".join(lines)

        findings = []
        if result.get("available") and result.get("native"):
            for name, nat in result["native"].items():
                if nat.get("error"):
                    continue
                raw = {
                    "sdk": "NATIVE", "title": f"{name}: "
                    f"{nat['counts']['function']} function(s), "
                    f"{nat['counts']['export']} export(s)",
                    "classification": "NATIVE",
                    "evidence": [{"level": "E3", "artifact": name,
                                  "detail": f"radare2 {nat['provider_version']}"}],
                    "falsification": ["static only — execution NOT OBSERVED"],
                }
                findings.append(core.normalize_finding(raw, self.spec.name, 1))
        if "jni_map" in result:
            n_na = sum(1 for e in result["jni_map"] if e["status"] != "EXACT")
            if n_na:
                raw = {
                    "sdk": "JNI", "title": f"{n_na} JNI export(s) NOT OBSERVED",
                    "classification": "JNI",
                    "evidence": [{"level": "E2", "artifact": "classes.dex",
                                  "detail": "native decl present, export not "
                                            "found in module"}],
                    "falsification": ["export may be in a different .so or "
                                      "resolved at runtime (NOT OBSERVED != "
                                      "IMPOSSIBLE)"],
                }
                findings.append(core.normalize_finding(raw, self.spec.name, 2))

        return core.EngineResult(
            intake={"sha256": sha, "package": None,
                    "dexCount": 0, "classCount": 0, "methodCount": 0,
                    "nativeLibs": result.get("libraries", [])},
            structural={"native": result},
            findings=findings,
            report_md=card,
            outputs={"report": rep, "card": card},
        )
