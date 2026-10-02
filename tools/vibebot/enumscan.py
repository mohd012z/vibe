# VibeBot — P13: obfuscated-enum detector (deterministic, pure core)
#
# lupoxyz technique #2 (the R8-shrunken enum): a Java/Kotlin `enum` compiled
# with R8 "shrink" becomes a class with
#   * N `static` fields whose type is the class's OWN type (the enum
#     instances are hoisted out of the backing array into static fields), and
#   * a `values()` method that rebuilds the array with a
#     `filled-new-array` (or `fill-array-data`) instruction.
# A normal class (non-enum) rarely has several static self-typed fields AND
# a values() that builds an array. That combination is the signature.
#
# /360 discipline: this is a STRUCTURAL heuristic over the decoded DEX, not
# a claim that the class IS an enum — the verdict is a graded signal, and the
# only thing we assert EXACT is the presence of the instruction sequence
# (E2, decoded bytecode). We never say "this is the enum Foo" (PROBABLE at
# best); we say "this class shows the R8-shrunken-enum signature with N
# candidate constant fields."
#
# Pure core (detect_enum / render_enums) takes compact per-class records and
# needs NO androguard -> fully unit-testable on synthetic records, exactly
# like claims.py / xmatch.py. The androguard glue that PRODUCES the records
# from a real DEX (enum_records) is a thin, separately-gated function.
from __future__ import annotations

GRAPH = dict


def _desc_type(desc: str) -> str:
    """A field descriptor 'Lcom/x/Enum;' -> 'com.x.Enum' (dot form)."""
    return (desc or "").strip().strip("L;").replace("/", ".")


def detect_enum(rec: dict) -> dict:
    """Classify one class record for the R8-shrunken-enum signature (PURE).

    rec keys (see enum_records):
      class        dot-form name
      superclass   dot-form superclass ("" if none)
      static_self  list of field names whose type == this class's own type
      values_meth  name of a STATIC method whose body uses a
                   filled-new-array / fill-array-data / new-array instruction
      enum_super   True if the superclass is java.lang.Enum (un-shrunken)

    Returns {verdict, n, fields, values, reason, level}:
      verdict  one of: "enum" (genuine, extends java.lang.Enum),
               "shrunken" (R8 signature), "partial" (weak signal),
               "none"
      level    evidence tag: E2 for the structural signal, E1 for the
               superclass fact, "" for none
    """
    cls = rec.get("class", "")
    sup = rec.get("superclass", "") or ""
    selfs = rec.get("static_self", []) or []
    n = len(selfs)
    values = rec.get("values_meth")
    is_enum_super = rec.get("enum_super", False) or sup.endswith("java.lang.Enum")

    # 1) un-shrunken enum: extends java.lang.Enum directly
    if is_enum_super:
        return {"verdict": "enum", "class": cls, "n": n,
                "fields": selfs, "values": values,
                "reason": "extends java.lang.Enum (un-shrunken)",
                "level": "E1"}

    # 2) R8-shrunken signature: >=2 static self-typed fields + a values()
    #    that builds an array
    if n >= 2 and values:
        return {"verdict": "shrunken", "class": cls, "n": n,
                "fields": selfs, "values": values,
                "reason": f"{n} static self-typed fields + {values}() "
                          "builds an array (R8-shrunken enum signature)",
                "level": "E2"}

    # 3) partial: self-typed statics present but no array-building values()
    #    (values may have been inlined/removed by the shrinker) — WEAKER
    if n >= 2:
        return {"verdict": "partial", "class": cls, "n": n,
                "fields": selfs, "values": values,
                "reason": f"{n} static self-typed fields but no array-building "
                          "values() (possible shrunken enum — weaker signal)",
                "level": "E2"}

    return {"verdict": "none", "class": cls, "n": n, "fields": selfs,
            "values": values, "reason": "", "level": ""}


def scan_enums(records: list[dict]) -> list[dict]:
    """Run detect_enum over every record; return the NON-none ones, sorted
    (shrunken first — the interesting case for patching), then enum, then
    partial, then by class name. PURE."""
    out = [detect_enum(r) for r in records]
    out = [e for e in out if e["verdict"] != "none"]
    order = {"shrunken": 0, "enum": 1, "partial": 2}
    out.sort(key=lambda e: (order.get(e["verdict"], 9), e["class"]))
    return out


def render_enums(enums: list[dict], sha: str) -> str:
    """Human/board rendering for the /map ENUM DETECTION section."""
    head = f"ENUM DETECTION  sha[:8]={sha[:8]}"
    if not enums:
        return head + "\n  no enum / R8-shrunken-enum signatures found"
    lines = [head, f"{len(enums)} candidate class(es)"]
    for e in enums:
        fstr = ", ".join(e["fields"][:8])
        if len(e["fields"]) > 8:
            fstr += f" …+{len(e['fields']) - 8}"
        lines.append(f"  [{e['level']}] {e['verdict']:<8} {e['class']}  "
                     f"n={e['n']} values={e['values'] or '-'}")
        lines.append(f"           fields: {fstr or '(none)'}")
        lines.append(f"           {e['reason']}")
    lines.append("")
    lines.append("  'shrunken' = the R8-shrunken enum signature (static "
                 "self-fields + array-building values()); a patch candidate "
                 "list, NOT a claim the class is an enum (PROBABLE ceiling).")
    return "\n".join(lines)


# ------------------------------------------------------------------ androguard glue
def _walk_methods(cls):
    """Yield (method_name, is_static, [instruction names]) for a DEX class."""
    for m in cls.get_methods():
        acc = m.get_access_flags_string() or ""
        static = "static" in acc
        names = []
        try:
            for ins in m.get_instructions():
                nm = ins.get_name() or ""
                if nm.startswith("filled-new-array") or nm == "fill-array-data" \
                        or nm == "new-array":
                    names.append(nm)
        except Exception:
            names = []
        yield (m.get_name(), static, names)


def enum_records(artifact: str) -> list[dict]:
    """Produce one compact class record per DEX class (androguard). Only the
    classes that could POSSIBLY be enums are recorded cheaply; the rest are
    still scanned (a shrunken enum has no other structural marker). Requires
    androguard."""
    from . import dexmapper
    from androguard.core.dex import DEX
    recs: list[dict] = []
    for dname, db in dexmapper._dex_bytes(artifact):
        d = DEX(db)
        for c in d.get_classes():
            cn = c.get_name().strip("L;").replace("/", ".")
            try:
                sup = (c.get_superclassname() or "").strip("L;").replace("/", ".")
            except Exception:
                sup = ""
            # static self-typed fields
            selfs: list[str] = []
            for f in c.get_fields():
                try:
                    acc = f.get_access_flags_string() or ""
                    if "static" not in acc:
                        continue
                    ftype = _desc_type(f.get_descriptor())
                    if ftype == cn:
                        selfs.append(f.get_name())
                except Exception:
                    continue
            # a static values()-style method that builds an array
            values = None
            for mname, static, arr in _walk_methods(c):
                if arr and static and mname in ("values", "valueOf"):
                    values = mname
                    break
            recs.append({"class": cn, "superclass": sup,
                         "static_self": selfs, "values_meth": values,
                         "enum_super": sup == "java.lang.Enum",
                         "dex": dname})
    return recs
