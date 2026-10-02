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


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]|\x1b\][^\x07]*\x07")


def _strip_ansi(s: str) -> str:
    """Strip ANSI SGR / OSC escape sequences. r2 6.x emits color codes on
    text output even when stdout is not a TTY (P18 probe: `afl` rows are
    wrapped in ESC[0m … ESC[0m). Pure. Defensive: JSON forms are unaffected
    (they carry no escapes), so this is safe on all runner output."""
    if not s:
        return s
    return _ANSI_RE.sub("", s)


def _loads_maybe(out: str):
    """Parse a JSON list/dict from r2 `*j` output, tolerating leading banner
    lines and trailing prompt junk. Returns the object, or None."""
    s = (out or "").strip()
    if not s:
        return None
    try:
        import json as _json
        return _json.loads(s)
    except Exception:
        pass
    # find the first '[' or '{' (some r2 builds print a WARN line first)
    for i, ch in enumerate(s):
        if ch in "[{":
            try:
                import json as _json
                return _json.loads(s[i:])
            except Exception:
                break
    return None


# ------------------------------------------------------------------ runner
class ProviderUnavailable(Exception):
    """The provider binary is not installed on this host (honest degrade)."""


class ProviderError(Exception):
    """The provider ran but produced an unusable result."""


class RadareRunner:
    """Invokes r2 as a subprocess (isolation invariant: never linked).

    r2 6.x invocation contract: flags BEFORE the file, quiet, no color:
    `r2 -e scr.color=0 -e bin.relocs.apply=true -q -c '<cmd>' <path>`.
    The historical `r2 <path> -c '<cmd>'` order is REJECTED by r2 6.x
    (it treats the command string as a second filename -> 'Cannot open').
    Returns ANSI-stripped stdout text. Raises ProviderUnavailable if r2 is
    missing, ProviderError on non-zero exit. A hard wall-clock cap (P6)
    applies to the subprocess. (P18: the argv order was never exercised
    against real r2 — every test used a FakeRunner — and broke on the r2
    6.2.2 upgrade that toolchain/android-tools.json 6.2.x targets.)
    """

    def __init__(self, bin: str = "r2", timeout: float = 60.0):
        self.bin = bin
        self.timeout = timeout

    def _have(self) -> bool:
        return router._which(self.bin)

    def run(self, path: str, cmd: str) -> str:
        if not self._have():
            raise ProviderUnavailable(f"{self.bin} not installed on this host")
        argv = [self.bin,
                "-e", "scr.color=0",
                "-e", "bin.relocs.apply=true",
                "-q", "-c", cmd, path]
        try:
            p = self._run(argv, self.timeout)
        except FileNotFoundError:
            raise ProviderUnavailable(f"{self.bin} not installed on this host")
        except subprocess.TimeoutExpired:
            raise ProviderError(f"r2 timed out after {self.timeout}s")
        if p.returncode != 0:
            raise ProviderError(f"r2 exit {p.returncode}: {p.stderr[:200].strip()}")
        return _strip_ansi(p.stdout)

    def _run(self, argv, timeout):
        """Subprocess seam (test capture point); real r2 call lives here."""
        return subprocess.run(list(argv), capture_output=True, text=True,
                              timeout=timeout)

    def version(self) -> str:
        try:
            out = subprocess.run([self.bin, "-v"], capture_output=True,
                                 text=True, timeout=10)
        except Exception:
            return "unknown"
        first = out.stdout.splitlines()[0] if out.stdout else "unknown"
        return _strip_ansi(first).strip()[:60]


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
    """r2 `aflj` (JSON list of {addr, name, size, realsz, ...}) or legacy
    `afl` text rows '0xADDR  size  name' (name optional). Pure. (P18: r2 6.x
    `afl` text gained a 4th delta-column AND ANSI wrapping — JSON is the
    stable contract, text kept for older r2 / FakeRunners.)"""
    data = _loads_maybe(out)
    if isinstance(data, list):
        fns = []
        for it in data:
            if not isinstance(it, dict) or "addr" not in it:
                continue
            try:
                va = int(it["addr"])
            except (TypeError, ValueError):
                continue
            size = it.get("size") or it.get("realsz") or 0
            name = it.get("name") or f"fcn.{va:08x}"
            fns.append({"va": va, "size": int(size), "name": str(name),
                        "r2_id": f"fcn.{va:08x}"})
        return fns
    fns = []
    for row in _parse_hex_rows(_strip_ansi(out)):
        toks = row.split()
        if not toks:
            continue
        if len(toks) >= 4:
            # r2 6.x text `afl`: '0xADDR  delta  size  name' (probed 2026-10-02;
            # the 4th column is what older 3-token parsers misread as the name)
            va = int(toks[0], 16)
            size = int(toks[2]) if re.match(r"^\d+$", toks[2]) else 0
            name = toks[3]
        else:
            # legacy 3-token '0xADDR  size  name' (r2 5.x / FakeRunner)
            va = int(toks[0], 16)
            size = int(toks[1]) if len(toks) > 1 and re.match(r"^\d+$", toks[1]) else 0
            name = toks[2] if len(toks) > 2 else f"fcn.{va:08x}"
        fns.append({"va": va, "size": size, "name": name,
                    "r2_id": f"fcn.{va:08x}"})
    return fns


def parse_exports(out: str) -> list[str]:
    """r2 `iEj` (JSON list of {name, ...}) or legacy text '0xADDR ... name'.
    Returns names, DEDUPED in first-seen order (r2 6 iEj lists the same
    symbol once per symtab AND once per dynsym — probed 2026-10-02). Pure."""
    data = _loads_maybe(out)
    if isinstance(data, list):
        names = []
        seen = set()
        for it in data:
            if isinstance(it, dict) and it.get("name"):
                n = str(it["name"])
                if n not in seen:
                    seen.add(n)
                    names.append(n)
        return names
    names = []
    for row in _parse_hex_rows(_strip_ansi(out)):
        toks = row.split()
        if len(toks) >= 2:
            names.append(toks[-1])
    return names


def parse_imports(out: str) -> list[dict]:
    """r2 `iij` (JSON list of {name, bind, type, plt}) or legacy 'sym:module'
    text. r2 6 iij carries NO source-library name (ELF dynamic imports are
    resolved by the dynamic linker, not named per-import) — module stays
    '' (honest), same as a legacy bare symbol. Pure."""
    data = _loads_maybe(out)
    if isinstance(data, list):
        imps = []
        for it in data:
            if isinstance(it, dict) and it.get("name"):
                imps.append({"name": str(it["name"]), "module": ""})
        return imps
    imps = []
    for ln in _strip_ansi(out).splitlines():
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
    """r2 `axtj` (JSON list of {from, type, opcode, fcn_name, refname, ...})
    or legacy `aXR`/`axt` text rows 'sym.NAME 0xADDR [CALL:--x] ...'. Returns
    the FROM addresses. Pure."""
    data = _loads_maybe(out)
    if isinstance(data, list):
        froms = []
        for it in data:
            if isinstance(it, dict) and "from" in it:
                try:
                    froms.append(int(it["from"]))
                except (TypeError, ValueError):
                    continue
        return froms
    # legacy `aXR`/`axt` text: real r2 prints "sym.NAME 0xADDR [CALL:--x] ..."
    # — the from-address is the FIRST 0x-hex token in the line, not always
    # token[0] (the symbol name leads). Scan for it.
    froms = []
    for ln in _strip_ansi(out).splitlines():
        m = re.search(r"0x[0-9a-fA-F]+", ln)
        if m:
            try:
                froms.append(int(m.group(0), 16))
            except ValueError:
                continue
    return froms


# ------------------------------------------------------------------ P15: native function-pattern classifier
# The ARM64 corpus insight (2026-10-02 external study): recognize a function
# by its NORMALIZED instruction SEQUENCE, not by hex bytes. lupoxyz shipped a
# memorized ARM hex-patch table; the durable form is these structural flags.
# Every flag is E3 (static XREF/disassembly evidence) — the SAME /360 claim
# discipline as the native provider, at the logic layer. The mnemonic
# vocabulary is the public ARMv8-A ISA (stable architecture facts, not
# reverse-engineered constants), and the patterns are compiler-output shapes
# observed in the exercism reference corpus.
def _adrp_add_pairs(mnems: list[str]) -> list[str]:
    """adrp Xd,label followed within 2 instructions by add Xd,Xd,:lo12:label —
    the position-independent address-load idiom (how every string/data
    reference is materialized). Returns the referenced symbol names."""
    pairs: list[str] = []
    for i, m in enumerate(mnems):
        a = m.lower()
        if not a.startswith("adrp "):
            continue
        lab = a.rsplit(" ", 1)[-1].strip()
        if not lab or lab.startswith("#"):
            continue
        for j in range(i + 1, min(i + 3, len(mnems))):
            m2 = mnems[j].lower()
            if m2.startswith("add ") and lab in m2 and ":lo12:" in m2:
                pairs.append(lab)
                break
    return pairs


def classify_function(mnems: list[str]) -> list[dict]:
    """Recognize a native function's LOGIC from its normalized ARM64 mnemonic
    sequence (PURE — no r2, no bytes). Each flag is structural evidence (E3):
    'this function's logic matches pattern X'. This is a candidate list for a
    human to re-validate (PROBABLE ceiling) — never a claim about what the app
    does. Returns [{id, pattern, evidence, reason}]."""
    if not mnems:
        return []
    low = [m.lower() for m in mnems]
    flags: list[dict] = []

    def _add(pid, pattern, ev, reason):
        flags.append({"id": pid, "pattern": pattern,
                      "evidence": "E3", "instrs": ev, "reason": reason})

    # popcount: clear-highest-set-bit loop (clz -> ror -> eor), no per-bit loop
    for i in range(len(low)):
        if low[i].startswith("clz") and i + 2 < len(low) \
                and low[i + 1].startswith("ror") and low[i + 2].startswith("eor"):
            _add("P1", "popcount-loop",
                 [mnems[i], mnems[i + 1], mnems[i + 2]],
                 "clz+ror+eor clear-highest-bit loop — popcount without a "
                 "per-bit loop")
            break
    # ASCII case-fold: orr Xd,Xd,#32 (force lower bit -> lowercase)
    for i, a in enumerate(low):
        if a.startswith("orr ") and ", #32" in a:
            _add("P2", "case-fold-scan", [mnems[i]],
                 "orr #32 — forces the ASCII lowercase bit (case-insensitive "
                 "match idiom)")
            break
    # bitset membership: `tst Xd, Xn, lsl #imm` — test a SINGLE bit of a
    # register (flag/permission check). The shifted form is the idiom; a bare
    # `tst Xd, Xn` (and `tst Xd, Xd` null-check) is deliberately NOT matched,
    # keeping the false-positive rate low. Documented precision trade.
    has_tst = re.search(r"\btst\s+\w+\s*,\s*\w+\s*,\s*lsl\s*#?\d+\b",
                        " ".join(low)) is not None
    if has_tst:
        has_lsl = any(a.startswith("lsl") for a in low)
        has_br = any(a == "bne" for a in low)
        _add("P3", "bitset-test",
             ["tst …, lsl #imm"] + (["lsl"] if has_lsl else [])
             + (["branch"] if has_br else []),
             "tst with a lsl #imm shift — single-bit (bitset) membership test "
             "(flag/permission check idiom)")
    # parity / even-odd test: tbb (bit 0 by definition) or tbz on bit #0
    # (a documented precision trade: a `tbz` on another bit index is a
    # generic bit-test, not parity, so it is NOT flagged). Real r2 `pdj`
    # names carry operands, so the `#0` operand is visible here.
    for m in mnems:
        a = m.lower()
        if a.startswith("tbb "):
            _add("P4", "tbz-bit0-parity", [m],
                 "tbb — branch on bit 0 (parity/even-odd test)")
            break
        if re.search(r"\btbz\s+\w+,\s*#?0\b", a):
            _add("P4", "tbz-bit0-parity", [m],
                 "tbz …, #0 — test bit 0 and branch (parity/even-odd test)")
            break
    # fused multiply-add: madd (3n+1 style)
    for i, a in enumerate(low):
        if a.startswith("madd") or a.startswith("mls"):
            _add("P5", "fused-madd", [mnems[i]],
                 "madd/mls — fused multiply-add (affine transform idiom)")
            break
    # position-independent string/data reference (adrp + add :lo12:)
    pairs = _adrp_add_pairs(mnems)
    if pairs:
        _add("P6", "string-ref-pair", pairs[:3],
             "adrp+add :lo12: — position-independent address load (string or "
             "data reference); a likely patch target")
    return flags


def classify_functions(fns_with_mnems: list[tuple[dict, list[str]]]) -> list[dict]:
    """Classify a batch of (function, mnemonics). Returns a list of
    {fcn, va, name, patterns:[...]} for the functions that matched >=1
    pattern (the interesting ones). Pure."""
    out = []
    for f, mnems in fns_with_mnems:
        pats = classify_function(mnems)
        if pats:
            out.append({"fcn": f.get("r2_id"), "va": f.get("va"),
                        "name": f.get("name"),
                        "patterns": [p["pattern"] for p in pats],
                        "details": pats})
    return out


def parse_disasm(out: str) -> list[str]:
    """r2 `pdj` (JSON) or `pd` (text) -> [mnemonic]. Tolerant: a JSON array
    of items, or one 'addr  name  rest' line each. Pure.

    Item shapes handled (both probed): r2 6.x `pdj` items carry `disasm`
    (the full mnemonic incl. operands, e.g. "mov rbp, rsp") with `opcode`
    identical; older r2 items carry `name` (mnemonic only) + separate
    `opcode`/`op` operands. P18: the r2-6 shape was never seen before, so
    real-r2 disasm silently returned [] (name-missing -> skipped)."""
    s = _strip_ansi(out or "").strip()
    if not s:
        return []
    mn: list[str] = []
    if s[0] == "[":
        data = _loads_maybe(s)
        if isinstance(data, list):
            for it in data:
                if not isinstance(it, dict):
                    continue
                if it.get("disasm"):
                    mn.append(str(it["disasm"]))
                    continue
                if it.get("name"):
                    name = str(it["name"]).split(".")[0]
                    # r2 keeps operands in a separate field ("opcode" in
                    # older r2, "op" in some builds) — append them so the
                    # full mnemonic is available for pattern matching.
                    op = it.get("opcode") or it.get("op")
                    if isinstance(op, str) and op.strip():
                        mn.append(f"{name} {op.strip()}")
                    else:
                        mn.append(name)
            return mn
        return mn
    for ln in s.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith(";"):
            continue
        toks = ln.split()
        if not toks or not re.match(r"^0x[0-9a-fA-F]+$", toks[0]):
            continue
        # after the address: skip consecutive pure-hex tokens (r2 `pd` emits
        # 4 opcode bytes: "53 00 c0 f2"), then the FIRST non-hex token is the
        # mnemonic. This handles both real `pd` (addr opcode... mnemonic) and
        # a simplified "addr mnemonic" line.
        i = 1
        while i < len(toks) and re.match(r"^[0-9a-fA-F]+$", toks[i]):
            i += 1
        if i < len(toks):
            mn.append(toks[i])
    return mn


def _classify_native_functions(native: dict, runner: "RadareLike | None" = None) -> None:
    """Attach a 'patterns' list to each function in native['functions'] by
    disassembling it via the runner (r2 `pdj`). Pure glue over the runner
    seam — no r2 required (works with FakeRunner). A disasm error leaves the
    function with an empty pattern list (honest: NOT OBSERVED, not a failure).
    Mutates native in place.

    P18 (r2 6.x, verified against real 6.2.2): the command is `aa; pdj N
    @0xVA` — `aa` warms up function recovery (without it, pdj disassembles
    raw bytes and fcn_addr=0), and the seek MUST be 0x-prefixed hex (a bare
    `@1129` is parsed as DECIMAL 1129 = 0x461 — probed)."""
    runner = runner or RadareRunner()
    for f in native.get("functions", []):
        try:
            dsize = f.get("size") or 0
            out = runner.run(native["path"],
                             f"aa; pdj {dsize} @0x{f['va']:x}")
            mnems = parse_disasm(out)
        except Exception:
            mnems = []
        f["mnemonics"] = mnems
        f["patterns"] = [p["pattern"] for p in classify_function(mnems)]
        f["pattern_details"] = classify_function(mnems)


# ------------------------------------------------------------------ native
def _r2_command_for(goal: str, path: str) -> str | None:
    return {
        "functions": "aa; aflj",
        "exports": "iEj",
        "imports": "iij",
        "strings": "izj",
        "xrefs": None,  # needs a target address (axtj)
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

    fns_out = runner.run(path, "aa; aflj")
    exps_out = runner.run(path, "iEj")
    imps_out = runner.run(path, "iij")

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

    # P15: native function-pattern classifier — recognize each function's
    # LOGIC by its normalized instruction sequence (E3). Best-effort: a
    # disasm failure leaves empty patterns (NOT OBSERVED), never an error.
    _classify_native_functions({"path": path, "functions": fns}, runner)

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
    if the provider can't answer (honest).

    P18 (r2 6.x, verified): uses `axtj` (aXR was removed in r2 6). In a
    position-independent .so, other code calls a function THROUGH ITS PLT
    STUB (sym.plt.X), so xrefs to the real function address come back EMPTY
    and the callers sit on the PLT stub instead (probed: sum3 -> plt.add).
    Fallback: if the direct query is empty, query the matching `sym.plt.<name>`
    stub and report its callers. The PLT hop is a PIC calling-convention
    artifact, not an identity claim — callers are E3 xref evidence either way.
    """
    runner = runner or RadareRunner()
    out = runner.run(native["path"], f"aa; axtj 0x{fcn_va:x}")
    froms = parse_xrefs(out, fcn_va)
    if not froms:
        # find this function's name in the analyzed set, then its PLT stub
        fname = None
        for f in native.get("functions", []):
            if f.get("va") == fcn_va:
                fname = f.get("name")
                break
        if fname:
            base = fname.rsplit(".", 1)[-1] if "." in fname else fname
            plt = f"sym.plt.{base}"
            for f in native.get("functions", []):
                if f.get("name") == plt:
                    out2 = runner.run(native["path"],
                                      f"aa; axtj 0x{f['va']:x}")
                    froms = parse_xrefs(out2, f["va"])
                    break
    return froms, native.get("segments", [])


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
        pats = f.get("patterns") or []
        if pats:
            lines.append(f"        [E3] logic pattern(s): {', '.join(pats)}")
    if c["function"] > limit:
        lines.append(f"    … {c['function'] - limit} more")
    # P15: a summary of the recognized logic patterns (the interesting ones)
    matched = [f for f in native["functions"] if f.get("patterns")]
    if matched:
        lines.append(f"  [E3] logic patterns recognized in {len(matched)} "
                     f"function(s) (structural match — re-validate; not a "
                     f"claim about app behavior):")
        for f in matched[:8]:
            lines.append(f"    {f['name']}: {', '.join(f['patterns'])}")
        if len(matched) > 8:
            lines.append(f"    … {len(matched) - 8} more")
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
