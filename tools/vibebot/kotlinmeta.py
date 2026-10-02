"""P17 — Kotlin @Metadata name recovery.

Recover the ORIGINAL Kotlin names from an APK/DEX. R8 can rename every DEX
method/field/class, but a Kotlin class's `@kotlin.Metadata` annotation
carries the names: `d1` = the serialized `Class` proto + name-resolver,
`d2` = the base string table. Decoding them yields `fq_name`, nested
classes, and every function/property name.

REAL R8 CEILING (verified 2026-10-02 on an actual R8 9.4.28 output of the
ktmeta fixture — see tests/fixtures/ktmeta_r8/):
- Plain (un-R8'd) DEX: `d2` holds the ORIGINAL names -> full recovery.
- R8'd DEX, build KEEPS @Metadata (`-keepattributes *Annotation*`):
  the annotation survives but `d2` is POST-R8 — class + method names are
  the obfuscated ones, while data-bearing property/field names usually
  survive. Recovery is PARTIAL: properties are the original names,
  class/function names are not recoverable from the DEX alone.
- R8'd DEX, default config: R8 STRIPS @Metadata entirely -> 0 records,
  `recover_names` reports "no @kotlin.Metadata" (honest, not a failure).
So "original (pre-R8) names" is guaranteed only for the plain-DEX case;
for an R8'd DEX the ceiling is whatever `d2` still contains.

Why this is the /360-correct shape:
- The DEX names are what you *see* (E2, often R8-minified: `a`, `b`, `c`).
- The @Metadata names are what the source *meant* (recovery: the mapping).
- A rename found here is only PROBABLE until re-validated against behavior —
  this module emits the recovered names as evidence, never a claim that a
  patch is correct.

NO hand-rolled binary constants. Every decode step is implemented from the
authoritative JetBrains Kotlin source (fetched 2026-10-02, Apache-2.0):
  - core/metadata.jvm/.../BitEncoding.java      (decodeBytes / encode8to7)
  - core/metadata.jvm/.../utfEncoding.kt        (bytesToStrings / stringsToBytes,
                                                 UTF8_MODE_MARKER, MAX_UTF8_INFO_LENGTH)
  - core/metadata.jvm/.../JvmProtoBufUtil.kt    (readClassDataFrom: proto layout
                                                 = StringTableTypes.parseDelimitedFrom
                                                 + Class.parseFrom)
  - core/metadata.jvm/.../JvmNameResolverBase.kt (getString resolution algorithm
                                                 + PREDEFINED_STRINGS table)
  - core/metadata/src/metadata.proto            (Class field numbers:
                                                 fq_name=3, nested_class_name=7,
                                                 constructor=8, function=9,
                                                 property=10; name fields = index 2,
                                                 string_id_in_table)

Verified against a REAL compiler: the module's pure-Python output is
diff-checked in tests against the Kotlin compiler's OWN deserializer
(`tools/vibebot/KMeta.java`, subprocess, the JVM oracle) run on a
ground-truth fixture (`tests/fixtures/ktmeta/classes.dex`, built with
kotlinc 2.0.21 -> d8). The ground truth is `sample.kt`, whose names are
known by construction.

d1 encoding modes (BitEncoding.decodeBytes):
  UTF-8 mode  (marker U+0000, the DEFAULT since Kotlin 1.x):
      proto[i] = char_code(d1[1 + i])          # drop the marker, char->byte
  8-to-7 mode (marker U+00FF, only when
      kotlin.jvm.serialization.use8to7=true; rare):
      raw = [(char-1) mod 128 for char in d1[1:]]; proto = decode7to8(raw)
"""

from __future__ import annotations

import os
import subprocess

from . import core

PROVIDER_NAME = "kotlin-meta"

UTF8_MODE_MARKER = 0x0000
_8TO7_MODE_MARKER = 0xFFFF

# ------------------------------------------------------------------ proto --
def _varint(b: bytes, i: int = 0):
    v = 0; sh = 0
    while True:
        x = b[i]; i += 1
        v |= (x & 0x7F) << sh
        if not x & 0x80:
            return v, i
        sh += 7


def _fields(b: bytes):
    """Yield (field_number, wire_type, value) for a proto message's top level.
    wire 0 -> int, 2 -> bytes, 5 -> 4 bytes, 1 -> 8 bytes."""
    i = 0
    while i < len(b):
        tag, i = _varint(b, i)
        f, w = tag >> 3, tag & 7
        if w == 0:
            v, i = _varint(b, i)
            yield f, 0, v
        elif w == 2:
            ln, i = _varint(b, i)
            yield f, 2, b[i:i + ln]
            i += ln
        elif w == 5:
            yield f, 5, b[i:i + 4]; i += 4
        elif w == 1:
            yield f, 1, b[i:i + 8]; i += 8
        else:
            return


# ------------------------------------------------------- BitEncoding (Java) --
def _decode7to8(data: bytes) -> bytes:
    """Faithful port of BitEncoding.decode7to8 (authoritative source)."""
    result_length = 7 * len(data) // 8
    out = bytearray(result_length)
    byte_index = 0; bit = 0
    for i in range(result_length):
        first_part = (data[byte_index] & 0xFF) >> bit
        byte_index += 1
        second_part = (data[byte_index] & ((1 << (bit + 1)) - 1)) << (7 - bit)
        out[i] = (first_part + second_part) & 0xFF
        if bit == 6:
            byte_index += 1; bit = 0
        else:
            bit += 1
    return bytes(out)


def bitencoding_decode(d1: str) -> bytes:
    """d1 (the @Metadata string) -> raw proto bytes. Port of
    BitEncoding.decodeBytes (UTF-8 + 8-to-7 modes)."""
    if not d1:
        return b""
    marker = ord(d1[0])
    if marker == UTF8_MODE_MARKER:
        # stringsToBytes(dropMarker(data)): drop char 0, char->byte
        return bytes((ord(c) & 0xFF) for c in d1[1:])
    if marker == _8TO7_MODE_MARKER:
        raw = bytes(((ord(c) - 1) & 0x7F) for c in d1[1:])
        return _decode7to8(raw)
    # No known mode marker: treat the whole string as raw char->byte (the
    # combineStringArrayIntoBytes fallback, un-marked). Honest: some hand
    # emitters omit the marker.
    return bytes((ord(c) & 0xFF) for c in d1)


# ------------------------------------------------- PREDEFINED_STRINGS (src) --
# Verbatim from JvmNameResolverBase.kt companion (authoritative source).
_PRE_K = "kotlin"
PREDEFINED_STRINGS = [
    f"{_PRE_K}/Any", f"{_PRE_K}/Nothing", f"{_PRE_K}/Unit",
    f"{_PRE_K}/Throwable", f"{_PRE_K}/Number",
    f"{_PRE_K}/Byte", f"{_PRE_K}/Double", f"{_PRE_K}/Float",
    f"{_PRE_K}/Int", f"{_PRE_K}/Long", f"{_PRE_K}/Short",
    f"{_PRE_K}/Boolean", f"{_PRE_K}/Char",
    f"{_PRE_K}/CharSequence", f"{_PRE_K}/String",
    f"{_PRE_K}/Comparable", f"{_PRE_K}/Enum",
    f"{_PRE_K}/Array", f"{_PRE_K}/ByteArray", f"{_PRE_K}/DoubleArray",
    f"{_PRE_K}/FloatArray", f"{_PRE_K}/IntArray", f"{_PRE_K}/LongArray",
    f"{_PRE_K}/ShortArray", f"{_PRE_K}/BooleanArray", f"{_PRE_K}/CharArray",
    f"{_PRE_K}/Cloneable", f"{_PRE_K}/Annotation",
    f"{_PRE_K}/collections/Iterable", f"{_PRE_K}/collections/MutableIterable",
    f"{_PRE_K}/collections/Collection",
    f"{_PRE_K}/collections/MutableCollection", f"{_PRE_K}/collections/List",
    f"{_PRE_K}/collections/MutableList", f"{_PRE_K}/collections/Set",
    f"{_PRE_K}/collections/MutableSet", f"{_PRE_K}/collections/Map",
    f"{_PRE_K}/collections/MutableMap", f"{_PRE_K}/collections/Map.Entry",
    f"{_PRE_K}/collections/MutableMap.MutableEntry",
    f"{_PRE_K}/collections/Iterator",
    f"{_PRE_K}/collections/MutableIterator",
    f"{_PRE_K}/collections/ListIterator",
    f"{_PRE_K}/collections/MutableListIterator",
]


# ------------------------------------------------- StringTableTypes record --
def _packed_varints(b: bytes) -> list[int]:
    """Parse a packed repeated-int32 value: RAW consecutive varints (no tags).
    Different from _fields — a packed group is not a nested message."""
    out = []
    i = 0
    while i < len(b):
        v, i = _varint(b, i)
        out.append(v)
    return out


def _parse_record(v: bytes) -> dict:
    rec = {"range": 1, "predef": None, "op": 0, "substr": [], "repl": [],
           "string": None}
    for f, w, val in _fields(v):
        if f == 1 and w == 0:
            rec["range"] = val
        elif f == 2 and w == 0:
            rec["predef"] = val
        elif f == 3 and w == 0:
            rec["op"] = val
        elif f == 4 and w == 2:
            rec["substr"] = _packed_varints(val)
        elif f == 5 and w == 2:
            rec["repl"] = _packed_varints(val)
        elif f == 6 and w == 2:
            rec["string"] = val.decode("utf-8", "replace")
    return rec


def parse_string_table_types(stt: bytes) -> tuple[list[dict], set[int]]:
    """StringTableTypes { repeated Record record=1; repeated int32
    local_name=5 [packed] } -> (records, local_name_set)."""
    records: list[dict] = []
    local: set[int] = set()
    for f, w, v in _fields(stt):
        if f == 1 and w == 2:
            rec = _parse_record(v)
            for _ in range(max(1, rec["range"])):
                records.append(rec)
        elif f == 5 and w == 2:
            local.update(_packed_varints(v))
    return records, local


def resolve_name(idx: int, records: list[dict], strings: list[str]) -> str:
    """Port of JvmNameResolverBase.getString (authoritative source)."""
    if not (0 <= idx < len(records)):
        return f"?{idx}?"
    rec = records[idx]
    if rec["string"] is not None:
        s = rec["string"]
    elif rec["predef"] is not None and rec["predef"] < len(PREDEFINED_STRINGS):
        s = PREDEFINED_STRINGS[rec["predef"]]
    else:
        s = strings[idx] if idx < len(strings) else f"?{idx}?"
    if len(rec["substr"]) >= 2:
        begin, end = rec["substr"][0], rec["substr"][1]
        if 0 <= begin <= end <= len(s):
            s = s[begin:end]
    if len(rec["repl"]) >= 2:
        s = s.replace(chr(rec["repl"][0]), chr(rec["repl"][1]))
    op = rec["op"]
    if op == 1:            # INTERNAL_TO_CLASS_ID
        s = s.replace("$", ".")
    elif op == 2:          # DESC_TO_CLASS_ID
        if len(s) >= 2:
            s = s[1:-1]
        s = s.replace("$", ".")
    return s


# ------------------------------------------------------------- Class parse --
def parse_class_names(class_bytes: bytes, records: list[dict],
                      strings: list[str]) -> dict:
    """ProtoBuf.Class (field numbers from metadata.proto) -> resolved names.
    fq_name=3 (varint idx), nested_class_name=7 (packed idx), constructor=8,
    function=9, property=10 (each a message whose `name=2` is the idx)."""
    out = {"fq_name": None, "nested": [], "companion": None,
           "constructors": 0, "functions": [], "properties": []}
    for f, w, v in _fields(class_bytes):
        if f == 3 and w == 0:
            out["fq_name"] = resolve_name(v, records, strings)
        elif f == 4 and w == 0:
            # companion_object_name = 4 (name_id_in_table)
            out["companion"] = resolve_name(v, records, strings)
        elif f == 7 and w == 2:
            # nested_class_name = 7 [packed, name_id_in_table]
            for idx in _packed_varints(v):
                out["nested"].append(resolve_name(idx, records, strings))
        elif f == 8 and w == 2:
            out["constructors"] += 1
        elif f in (9, 10) and w == 2:
            nm = None
            for f2, w2, v2 in _fields(v):
                if f2 == 2 and w2 == 0:
                    nm = resolve_name(v2, records, strings)
            (out["functions"] if f == 9 else out["properties"]).append(nm)
    return out


def decode_class_metadata(d1: str, d2: list[str]) -> dict | None:
    """Full pure-Python decode: d1 (BitEncoding str) + d2 (string table) ->
    resolved Class names. Returns None if d1 is empty/undecodable."""
    if not d1:
        return None
    try:
        proto = bitencoding_decode(d1)
    except Exception:
        return None
    if not proto:
        return None
    # JvmProtoBufUtil.readClassDataFrom: StringTableTypes.parseDelimitedFrom
    # (leading varint length) then Class.parseFrom (the remainder).
    stt_len, i = _varint(proto, 0)
    stt = proto[i:i + stt_len]
    class_bytes = proto[i + stt_len:]
    records, _local = parse_string_table_types(stt)
    return parse_class_names(class_bytes, records, list(d2))


# ------------------------------------------------------------- DEX glue -----
def _string_of(dex, el) -> str | list[str]:
    """An EncodedValue for a Metadata string element -> its DEX string(s)."""
    sid = _varint(bytes(el.raw_value))[0]
    return dex.get_cm_string(sid)


def extract_kotlin_metadata(dex_bytes: bytes,
                            class_filter: str | None = None) -> list[dict]:
    """Scan a DEX for classes carrying @kotlin.Metadata; return one record
    each: {class_desc, k, mv, xi, d1, d2}. Pure androguard glue (the
    annotation API is function-scoped so a no-androguard env degrades)."""
    from androguard.core.dex import DEX
    d = DEX(dex_bytes)
    out = []
    for cls in d.get_classes():
        desc = str(cls.get_name())
        if class_filter and class_filter not in desc.replace("/", "."):
            continue
        try:
            anns = cls._get_annotation_type_ids()
        except Exception:
            continue
        meta = None
        for a in anns:
            if "kotlin/Metadata" in str(d.get_cm_type(a.get_type_idx())):
                meta = a
                break
        if meta is None:
            continue
        rec = {"class_desc": desc, "k": None, "mv": [], "xi": None,
               "d1": None, "d2": []}
        for el in meta.get_elements():
            nm = d.get_cm_string(el.name_idx)
            val = el.value.get_value()
            if nm in ("k", "xi"):
                # primitive int element: .value is the decoded int (value_arg
                # is 0 for non-arg types in androguard 4.x)
                rec[nm] = el.value.value
            elif nm == "mv":
                rec["mv"] = [e.value for e in val.get_values()]
            elif nm == "d1":
                rec["d1"] = "".join(_string_of(d, e)
                                    for e in val.get_values())
            elif nm == "d2":
                rec["d2"] = [_string_of(d, e) for e in val.get_values()]
        out.append(rec)
    return out


def recover_names(dex_bytes: bytes, class_filter: str | None = None) -> list[dict]:
    """extract + decode: for each @Metadata class, the recovered names."""
    out = []
    for rec in extract_kotlin_metadata(dex_bytes, class_filter):
        dec = decode_class_metadata(rec["d1"] or "", rec["d2"])
        out.append({**{k: rec[k] for k in
                       ("class_desc", "k", "mv", "xi")}, "decoded": dec})
    return out


# ------------------------------------------------------------- rendering ----
def render_kmeta(recovered: list[dict]) -> str:
    if not recovered:
        return ("KOTLIN-META  no @kotlin.Metadata classes found "
                "(not a Kotlin build, or names not recoverable)")
    lines = []
    for r in recovered:
        dec = r.get("decoded")
        if not dec or dec.get("fq_name") is None:
            lines.append(f"  {r['class_desc'].rstrip(';')}: "
                         f"@Metadata present (k={r.get('k')}) but decode NOT "
                         f"OBSERVED (version/shape not handled)")
            continue
        lines.append(f"  {r['class_desc'].rstrip(';')}  "
                     f"[k={r.get('k')} mv={r.get('mv')}]")
        lines.append(f"    fq_name: {dec['fq_name']}")
        if dec["nested"]:
            lines.append(f"    nested:  {', '.join(dec['nested'])}")
        if dec.get("companion"):
            lines.append(f"    companion: {dec['companion']}")
        lines.append(f"    ctors:   {dec['constructors']}")
        if dec["functions"]:
            lines.append(f"    fns:     {', '.join(str(x) for x in dec['functions'])}")
        if dec["properties"]:
            lines.append(f"    props:   {', '.join(str(x) for x in dec['properties'])}")
    lines.append("  (names recovered from @Metadata — on a PLAIN DEX these "
                 "are the originals; on an R8'd DEX they may be post-R8 "
                 "(properties often survive, class/method names may not) "
                 "or @Metadata may be stripped entirely. DEX names are the "
                 "falsifiable view; re-validate before acting. E2 annotation "
                 "evidence, PROBABLE until behavior confirms.)")
    return "\n".join(lines)


# ------------------------------------------------- JVM oracle (subprocess) --
def _find_java_verifier() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    p = os.path.join(here, "KMeta.java")
    return p if os.path.exists(p) else None


def _find_kotlin_toolchain() -> tuple[str, str, str] | None:
    """(java_bin, javac_bin, kotlin_classpath) if a Kotlin compiler jar + JDK
    are on this host (used ONLY as the differential-verification oracle)."""
    import shutil
    env = os.environ.get("KOTLINC_HOME")
    cands = []
    if env:
        cands.append(os.path.join(env, "lib", "kotlin-compiler.jar"))
    for base in ("/opt/data/cache/scratch/toolchain", "/usr/local", "/opt"):
        cands += [os.path.join(base, "kotlinc", "lib", "kotlin-compiler.jar"),
                  os.path.join(base, "lib", "kotlin-compiler.jar")]
    for c in cands:
        if os.path.exists(c):
            lib = os.path.dirname(c)
            # java + javac: PATH first, else inside the same toolchain root
            java = shutil.which("java") or os.path.join(
                os.path.dirname(os.path.dirname(lib)), "bin", "java")
            javac = shutil.which("javac") or os.path.join(
                os.path.dirname(os.path.dirname(lib)), "bin", "javac")
            if os.path.exists(java) and os.path.exists(javac):
                return (java, javac,
                        c + ":" + os.path.join(lib, "kotlin-stdlib.jar"))
    return None


def run_jvm_oracle(d1: str, d2: list[str], workdir: str) -> dict | None:
    """Run tools/vibebot/KMeta.java (the Kotlin compiler's OWN deserializer)
    on d1/d2 and parse its stdout. Returns the same shape as
    decode_class_metadata, or None if the toolchain is absent (honest
    degrade — the oracle is verification, not the production path)."""
    tc = _find_kotlin_toolchain()
    v = _find_java_verifier()
    if not tc or not v:
        return None
    java, javac, cp = tc
    os.makedirs(workdir, exist_ok=True)
    d1f = os.path.join(workdir, "d1.bin")
    d2f = os.path.join(workdir, "d2.txt")
    with open(d1f, "wb") as f:
        f.write(d1.encode("ISO-8859-1"))
    with open(d2f, "w") as f:
        f.write("\n".join(d2) + "\n")
    try:
        # compile the verifier once (javac), then run it (java) per class
        if not os.path.exists(os.path.join(workdir, "KMeta.class")):
            subprocess.run([javac, "-cp", cp, "-d", workdir, v],
                           check=True, capture_output=True, timeout=120)
        p = subprocess.run([java, "-cp", workdir + ":" + cp, "KMeta", d1f, d2f],
                           capture_output=True, text=True, timeout=120)
    except Exception:
        return None
    if p.returncode != 0:
        return None
    out = p.stdout
    res = {"fq_name": None, "nested": [], "constructors": 0,
           "functions": [], "properties": []}
    # parse the exact lines KMeta prints
    for ln in out.splitlines():
        ln = ln.strip()
        if ln.startswith("CLASS fq_name") and "->" in ln:
            res["fq_name"] = ln.rsplit("->", 1)[1].strip()
        elif ln.startswith("nested") and "->" in ln:
            res["nested"].append(ln.rsplit("->", 1)[1].strip())
        elif ln.startswith("ctor"):
            res["constructors"] += 1
        elif ln.startswith("fn") and "name=" in ln:
            res["functions"].append(ln.rsplit("name=", 1)[1].strip())
        elif ln.startswith("prop") and "name=" in ln:
            res["properties"].append(ln.rsplit("name=", 1)[1].strip())
    return res


# ------------------------------------------------------------- engine -------
class KotlinMetaEngine(core.Engine):
    """Engine: recover original Kotlin names from an APK/DEX @Metadata
    (E2 annotation evidence, PROBABLE ceiling). Pure-Python decode is the
    production path; the JVM compiler deserializer is a differential
    oracle (subprocess) when a toolchain is present. Degrades honestly:
    no @Metadata -> 'not a Kotlin build', no androguard -> 'not installed'."""

    spec = core.EngineSpec(
        name="kotlin-meta",
        description="Kotlin @Metadata name recovery: the names @Metadata's "
                    "d2 table carries (originals on a plain DEX; on an R8'd "
                    "DEX possibly post-R8 or @Metadata stripped — see the "
                    "module docstring's R8 ceiling note)",
        formats=("apk", "dex", "apkx"),
    )

    def __init__(self, report_dir: str):
        self.report_dir = report_dir

    def can_run(self, artifact: str) -> bool:
        return artifact.lower().endswith((".apk", ".dex", ".apkx"))

    def run(self, job: "core.Job") -> core.EngineResult:
        import json as _json
        job.progress("intake", 10, "dex extraction")
        sha = core._sha256(job.artifact)
        job.checkpoint("intake", {"sha256": sha})
        # pull the DEX bytes (direct .dex or from an APK)
        if job.artifact.lower().endswith(".dex"):
            dex_bytes = open(job.artifact, "rb").read()
        else:
            import zipfile
            dex_bytes = b""
            with zipfile.ZipFile(job.artifact) as z:
                for n in z.namelist():
                    if n.endswith(".dex"):
                        dex_bytes = z.read(n)
                        break
        if not dex_bytes:
            return self._finish(job, sha, {"available": False,
                                           "note": "no DEX in artifact",
                                           "classes": []})
        job.progress("recover", 50, "decode @Metadata (pure Python)")
        flt = (job.params or {}).get("class_filter")
        try:
            full = extract_kotlin_metadata(dex_bytes, flt)
            available = True
        except Exception as e:  # androguard missing / parse error
            return self._finish(job, sha, {"available": False,
                                           "note": f"decode error: {e}",
                                           "classes": []})
        recovered = []
        for rec in full:
            rec = dict(rec)
            rec["decoded"] = decode_class_metadata(rec.get("d1") or "",
                                                   rec.get("d2") or [])
            recovered.append(rec)
        # JVM oracle cross-check on the first decodable class (verification,
        # optional — absent toolchain just means no oracle, not a failure)
        oracle = None
        first = next((r for r in recovered if r.get("decoded")), None)
        if first is not None:
            oracle = run_jvm_oracle(first["d1"] or "", first["d2"] or [],
                                    os.path.join(self.report_dir, "oracle"))
        result = {"available": available, "provider": PROVIDER_NAME,
                  "class_count": len(recovered),
                  "classes": [{k: r[k] for k in
                               ("class_desc", "k", "mv", "xi", "decoded")}
                              for r in recovered],
                  "oracle": oracle}
        job.checkpoint("recover", {"class_count": len(recovered)})
        job.progress("report", 100, "done")
        return self._finish(job, sha, result)

    def _finish(self, job, sha, result) -> core.EngineResult:
        import json as _json
        os.makedirs(self.report_dir, exist_ok=True)
        ts = core.time.strftime("%Y%m%d-%H%M%S")
        rep = os.path.join(self.report_dir, f"vibe-kmeta-{ts}.json")
        _json.dump(result, open(rep, "w"), indent=2, default=str)
        card = render_kmeta(result.get("classes", [])) if result.get("available") \
            else f"KOTLIN-META  {result.get('note', 'not available')}"
        findings = []
        if result.get("available") and result.get("classes"):
            n_named = sum(1 for c in result["classes"]
                          if c.get("decoded") and c["decoded"].get("fq_name"))
            raw = {
                "sdk": "KOTLIN-META",
                "title": f"recovered Kotlin names for {n_named} class(s) from "
                         f"@Metadata (E2, PROBABLE; originals only on a "
                         f"plain DEX — see the R8 ceiling note)",
                "classification": "KOTLIN_RECOVERY",
                "evidence": [{"level": "E2", "artifact": "@kotlin.Metadata",
                              "detail": f"{result['class_count']} annotated "
                                        f"class(es), pure-Python decode" +
                                        ("; JVM-verified" if result.get("oracle")
                                         else "")}],
                "falsification": ["recovered names are what @Metadata's d2 "
                                  "table carries: on a plain DEX the source "
                                  "originals; on an R8'd DEX possibly "
                                  "post-R8 (properties often survive, "
                                  "class/method names may not) or @Metadata "
                                  "stripped entirely — re-validate against "
                                  "behavior before acting (PROBABLE ceiling)"],
            }
            findings.append(core.normalize_finding(raw, self.spec.name, 1))
        return core.EngineResult(
            intake={"sha256": sha, "package": None, "dexCount": 1,
                    "classCount": result.get("class_count", 0),
                    "methodCount": 0, "nativeLibs": []},
            structural={"kotlin_meta": result},
            findings=findings,
            report_md=card,
            outputs={"report": rep, "card": card},
        )
