"""vibebot.smali — canonical Dalvik opcode table + /smali query, plus
/base and /hash helpers.

The table is the official Dalvik bytecode set (source.android.com /
dalvik-bytecode spec), reduced to the opcodes an analyst actually looks up
while tracing app code. Opcode VALUES and FORMATS are taken verbatim from the
spec, not reconstructed from memory — an earlier draft had wrong values
(e.g. new-instance, invoke-virtual, return-void) and was corrected against
the spec + androguard's ground-truth decode of a real fixture.

NOTE on format codes: these are the spec's FORMAT names (10x, 12x, 21c, 22t,
35c, 3rc, ...). /smali reports them for reference. Bit-level assemble/
disassemble of those formats is intentionally NOT in P2 (see study note) —
it needs a ground-truth decoder cross-check and lands in P3.
"""

from __future__ import annotations

# OPCODE_TABLE: dalvik opcode byte (0x00..0xff) -> (name, fmt, desc).
# Values per the official Dalvik bytecode spec. Reduced to high-value
# opcodes (the full 257 is available in the spec; the DEX Mapper engine
# decodes real bytecode via androguard, which is the correct path).
OPCODE_TABLE: dict[int, tuple[str, str, str]] = {
    # ---- move / result / exception
    0x00: ("nop", "10x", "no operation"),
    0x01: ("move", "12x", "copy non-object value vA, vB"),
    0x02: ("move/from16", "22x", "copy non-object value, 16-bit regs"),
    0x03: ("move/16", "32x", "copy non-object value, 16-bit regs"),
    0x04: ("move-wide", "12x", "copy 64-bit value pair"),
    0x05: ("move-wide/from16", "22x", "copy 64-bit value, 16-bit regs"),
    0x06: ("move-wide/16", "32x", "copy 64-bit value, 16-bit regs"),
    0x07: ("move-object", "12x", "copy object reference"),
    0x08: ("move-object/from16", "22x", "copy object reference, 16-bit regs"),
    0x09: ("move-object/16", "32x", "copy object reference, 16-bit regs"),
    0x0a: ("move-result", "11x", "move single-word invoke result"),
    0x0b: ("move-result-wide", "11x", "move double-word invoke result"),
    0x0c: ("move-result-object", "11x", "move object invoke result"),
    0x0d: ("move-exception", "11x", "save a just-caught exception"),
    # ---- return
    0x0e: ("return-void", "10x", "return from a void method"),
    0x0f: ("return", "11x", "return single-width value"),
    0x10: ("return-wide", "11x", "return double-width value"),
    0x11: ("return-object", "11x", "return object reference"),
    # ---- constants
    0x12: ("const/4", "11n", "load 4-bit const to register"),
    0x13: ("const/16", "21s", "load 16-bit const to register"),
    0x14: ("const", "31i", "load 32-bit const to register"),
    0x15: ("const/high16", "21h", "load 32-bit const, low 16 zero"),
    0x16: ("const-wide/16", "21s", "load 16-bit const to 64-bit reg"),
    0x17: ("const-wide/32", "31i", "load 32-bit const to 64-bit reg"),
    0x18: ("const-wide", "51l", "load 64-bit const to register pair"),
    0x19: ("const-wide/high16", "21h", "load 64-bit const, high 16"),
    0x1a: ("const-string", "21c", "load string reference by index"),
    0x1b: ("const-string/jumbo", "31c", "load string ref, 32-bit index"),
    0x1c: ("const-class", "21c", "load Class object for type by index"),
    # ---- monitors / casts / refs
    0x1d: ("monitor-enter", "11x", "acquire monitor for object ref"),
    0x1e: ("monitor-exit", "11x", "release monitor for object ref"),
    0x1f: ("check-cast", "21c", "assert object is of a given type"),
    0x20: ("instance-of", "22c", "test if object is of a given type"),
    0x21: ("array-length", "12x", "get length of an array"),
    0x22: ("new-instance", "21c", "create a new object instance"),
    0x23: ("new-array", "22c", "create a new array of given type/size"),
    0x24: ("filled-new-array", "35c", "create filled array (single-word)"),
    0x25: ("filled-new-array/range", "3rc", "create filled array, reg range"),
    0x26: ("fill-array-data", "31t", "fill array with table data"),
    0x27: ("throw", "11x", "throw the exception in vA"),
    # ---- branches
    0x28: ("goto", "10t", "unconditional branch"),
    0x29: ("goto/16", "20t", "unconditional branch, 16-bit offset"),
    0x2a: ("goto/32", "30t", "unconditional branch, 32-bit offset"),
    0x2b: ("packed-switch", "31t", "jump via packed table (switch)"),
    0x2c: ("sparse-switch", "31t", "jump via sparse table (switch)"),
    0x2d: ("cmpl-float", "23x", "compare floats, lt bias"),
    0x2e: ("cmpg-float", "23x", "compare floats, gt bias"),
    0x2f: ("cmpl-double", "23x", "compare doubles, lt bias"),
    0x30: ("cmpg-double", "23x", "compare doubles, gt bias"),
    0x31: ("cmp-long", "23x", "compare long values"),
    0x32: ("if-eq", "22t", "branch if vA == vB"),
    0x33: ("if-ne", "22t", "branch if vA != vB"),
    0x34: ("if-lt", "22t", "branch if vA < vB"),
    0x35: ("if-ge", "22t", "branch if vA >= vB"),
    0x36: ("if-gt", "22t", "branch if vA > vB"),
    0x37: ("if-le", "22t", "branch if vA <= vB"),
    0x38: ("if-eqz", "21t", "branch if vA == 0"),
    0x39: ("if-nez", "21t", "branch if vA != 0"),
    0x3a: ("if-ltz", "21t", "branch if vA < 0"),
    0x3b: ("if-gez", "21t", "branch if vA >= 0"),
    0x3c: ("if-gtz", "21t", "branch if vA > 0"),
    0x3d: ("if-lez", "21t", "branch if vA <= 0"),
    # ---- array get/set
    0x44: ("aget", "23x", "get int array element"),
    0x45: ("aget-wide", "23x", "get long array element"),
    0x46: ("aget-object", "23x", "get object array element"),
    0x4b: ("aput", "23x", "set int array element"),
    0x4c: ("aput-wide", "23x", "set long array element"),
    0x4d: ("aput-object", "23x", "set object array element"),
    # ---- instance field (iget/iput) — 0x52..0x5f
    0x52: ("iget", "22c", "get int instance field"),
    0x54: ("iget-object", "22c", "get object instance field"),
    0x59: ("iput", "22c", "set int instance field"),
    0x5b: ("iput-object", "22c", "set object instance field"),
    # ---- static field (sget/sput) — 0x60..0x6d
    0x60: ("sget", "21c", "get int static field"),
    0x62: ("sget-object", "21c", "get object static field"),
    0x67: ("sput", "21c", "set int static field"),
    0x69: ("sput-object", "21c", "set object static field"),
    # ---- invokes (35c = register list; 3rc = register range)
    0x6e: ("invoke-virtual", "35c", "call instance method on object"),
    0x6f: ("invoke-super", "35c", "call superclass instance method"),
    0x70: ("invoke-direct", "35c", "call direct (static/constructor) method"),
    0x71: ("invoke-static", "35c", "call static method"),
    0x72: ("invoke-interface", "35c", "call interface method"),
    0x74: ("invoke-virtual/range", "3rc", "invoke-virtual over register range"),
    0x75: ("invoke-super/range", "3rc", "invoke-super over register range"),
    0x76: ("invoke-direct/range", "3rc", "invoke-direct over register range"),
    0x77: ("invoke-static/range", "3rc", "invoke-static over register range"),
    0x78: ("invoke-interface/range", "3rc", "invoke-interface over register range"),
    # ---- unary (neg/not/convert) — 0x7b..0x8f
    0x7b: ("neg-int", "12x", "negate int"),
    0x7f: ("neg-float", "12x", "negate float"),
    0x81: ("int-to-long", "12x", "convert int to long"),
    0x82: ("int-to-float", "12x", "convert int to float"),
    0x84: ("long-to-int", "12x", "convert long to int"),
    0x87: ("float-to-int", "12x", "convert float to int"),
    # ---- binary ops (binop) — 0x90..0xaf
    0x90: ("add-int", "23x", "add two int values"),
    0x91: ("sub-int", "23x", "subtract two int values"),
    0x92: ("mul-int", "23x", "multiply two int values"),
    0x93: ("div-int", "23x", "integer divide"),
    0x94: ("rem-int", "23x", "integer remainder"),
    0x95: ("and-int", "23x", "bitwise AND"),
    0x96: ("or-int", "23x", "bitwise OR"),
    0x97: ("xor-int", "23x", "bitwise XOR"),
    0x98: ("shl-int", "23x", "left shift int"),
    0x99: ("shr-int", "23x", "arithmetic right shift int"),
    0x9a: ("ushr-int", "23x", "logical right shift int"),
    # ---- binary /2addr — 0xb0..0xcf
    0xb0: ("add-int/2addr", "12x", "add, result overwrites 1st operand"),
    0xb1: ("sub-int/2addr", "12x", "subtract, result overwrites 1st operand"),
    0xb2: ("mul-int/2addr", "12x", "multiply, result overwrites 1st operand"),
    0xb3: ("div-int/2addr", "12x", "divide, result overwrites 1st operand"),
    0xb4: ("rem-int/2addr", "12x", "remainder, result overwrites 1st operand"),
    0xb5: ("and-int/2addr", "12x", "AND, result overwrites 1st operand"),
    0xb6: ("or-int/2addr", "12x", "OR, result overwrites 1st operand"),
    0xb7: ("xor-int/2addr", "12x", "XOR, result overwrites 1st operand"),
    0xb8: ("shl-int/2addr", "12x", "left shift, 2addr"),
    0xb9: ("shr-int/2addr", "12x", "arithmetic right shift, 2addr"),
    0xba: ("ushr-int/2addr", "12x", "logical right shift, 2addr"),
}

NAME_TO_OPCODE: dict[str, int] = {v[0]: k for k, v in OPCODE_TABLE.items()}


def opcode_count() -> int:
    return len(OPCODE_TABLE)


def _row(k: int, v: tuple) -> dict:
    return {"code": k, "name": v[0], "format": v[1], "desc": v[2]}


def query(q: str) -> list[dict]:
    """/smali: exact name, opcode (0x../decimal), or substring.
    Returns list of rows (empty when nothing matches)."""
    q = q.strip()
    if not q:
        return []
    if q.lower().startswith("0x"):
        try:
            val = int(q, 16)
        except ValueError:
            return []
        hit = OPCODE_TABLE.get(val)
        return [_row(val, hit)] if hit else []
    if q.isdigit():
        val = int(q)
        if val in OPCODE_TABLE:
            return [_row(val, OPCODE_TABLE[val])]
        return []
    ql = q.lower()
    exact = [(k, v) for k, v in OPCODE_TABLE.items() if v[0].lower() == ql]
    if exact:
        return [_row(k, v) for k, v in exact]
    partial = [(k, v) for k, v in OPCODE_TABLE.items()
               if ql in v[0].lower() or ql in v[2].lower() or ql == v[1]]
    return [_row(k, v) for k, v in sorted(partial)]


def to_base(n: int, base: int) -> str:
    """Format integer n in the given base (2..36), lowercase."""
    if not (2 <= base <= 36):
        raise ValueError("base must be 2..36")
    digits = "0123456789abcdefghijklmnopqrstuvwxyz"
    if n == 0:
        return "0"
    neg, m = n < 0, abs(n)
    out = ""
    while m:
        m, r = divmod(m, base)
        out = digits[r] + out
    return ("-" + out) if neg else out


def base_convert(value: str, src_base: int, dst_base: int) -> dict:
    if not (2 <= src_base <= 36):
        return {"error": "src base must be 2..36"}
    try:
        n = int(str(value), src_base)
    except (ValueError, TypeError):
        return {"error": f"cannot read {value!r} as base-{src_base}"}
    return {"value": value, "from": src_base, "to": dst_base,
            "result": to_base(n, dst_base)}
