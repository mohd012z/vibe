# VibeBot — P12: Cross-version method fingerprinting (deterministic, pure core)
#
# /360 stage: "learns only from VALIDATED outcomes" — but today a validated
# finding dies with the APK it was made on. When an app ships v2, every
# method is re-identified from scratch. This module gives each method a
# stable, address-independent fingerprint of its LOGIC, so a finding
# validated on v1 can be carried to the matching method on v2 as a candidate
# (never silently promoted to EXACT — the six-state contract still applies).
#
# Ported from ghidra-mcp's computeStrictHash (normalized opcode sequence ->
# SHA-256), adapted to DEX. The one DEX-specific adaptation, and the whole
# point of it: DEX virtual registers (v0, v1, …) are allocated by the
# compiler and get RENUMBERED between builds, whereas native registers (x0,
# r0) are architecturally fixed. So DEX registers are bucketed to "REG"
# (ghidra keeps them; we drop them) — otherwise two identical methods in
# two builds would never match. What we KEEP as identity signals:
#   * the instruction mnemonic sequence (the logic)
#   * const-string literals (STR:<val>) — the text a method speaks
#   * call targets (CALL:<class.method>) — which APIs it uses
#   * small immediates (IMM:<v>) — but large ones are bucketed (IMM_LARGE),
#     since a data offset / size that moves across builds is not "different
#     logic"
# and what we NORMALIZE AWAY (build-dependent, not identity):
#   * registers v\d+ -> REG
#   * branch targets (offsets / pseudo-labels) -> a single L  token — so a
#     branch's KIND and CONDITION survive, its distance does not. This is the
#     documented limitation: the fingerprint captures control-flow *type*, not
#     jump distance (a loop of a different size still matches).
#
# The matching core (match_cross_version) is PURE over two fingerprint maps
# — no androguard, no bytes — so it is fully unit-testable on synthetic maps,
# exactly like claims.py. The androguard glue that PRODUCES the fingerprint
# map from a real DEX is a thin, separately-gated function.

from __future__ import annotations

import hashlib
import os
import re

from . import core

GRAPH = dict

# the six-state contract (same states, same discipline, as EntityResolver)
STATES = ("EXACT", "STRONG", "PROBABLE", "AMBIGUOUS", "CONFLICT", "UNRESOLVED")

# branch-style mnemonics whose LAST operand is a (renumbered) label
_BRANCH_PREFIXES = ("goto", "if", "switch")
_CONST_PREFIXES = ("const",)
_STR_MNEMONICS = ("const-string", "const-string/jumbo")
_LARGE_IMM = 0x10000


def normalize_instruction(mnemonic: str, output: str) -> list[str]:
    """Normalize one decoded instruction to operand identity tokens (PURE).

    Returns a list of operand tokens (the mnemonic is NOT included here — the
    caller joins it). Deterministic: same (mnemonic, output) -> same tokens.
    """
    out = (output or "").strip()

    # invoke-* : keep the call target (class.method) — a strong identity
    # signal; drop the (renumbered) register list that precedes it.
    if mnemonic.startswith("invoke") and "->" in out:
        lhs, rhs = out.split("->", 1)
        cls = lhs.split(",")[-1].strip().strip("L;").replace("/", ".")
        meth = rhs.split("(", 1)[0].strip()
        # class + DOT + method — the dot keeps the two tokens aligned with a
        # Radare-resolved "Class.method" target (cross-provider matching).
        return [f"CALL:{cls}.{meth}"]

    # const-string : keep the literal text (what the method says)
    if mnemonic in _STR_MNEMONICS:
        m = re.search(r'"((?:[^"\\]|\\.)*)"\s*$', out)
        return [f"STR:{m.group(1) if m else out}"]

    # const / const-wide / const/4 / const/16 : keep small immediates,
    # bucket large ones (a moved offset/size is not different logic).
    # Keep the base explicit: androguard prints const-wide in hex with no
    # 0x prefix and a trailing L ("const-wide v0, 0x800000000L"), which
    # would otherwise collide with a decimal reading of the same digits.
    if mnemonic.startswith(_CONST_PREFIXES):
        num = None
        for piece in out.split(","):
            p = piece.strip().rstrip("L")
            # skip a leading register operand ("v0" / "h1" / "v0, v1"); and
            # androguard prints const/4 + const/16 as DECIMAL (no 0x, no #)
            if p.startswith(("v", "h")):
                continue
            if p.startswith("0x") and re.fullmatch(r"0x[0-9a-fA-F]+", p):
                num = p
                break
            if re.fullmatch(r"-?\d+", p):
                num = p
        if num is None:
            return []
        # parse in the base as spelled (hex 0x / decimal) — the VALUE is the
        # identity signal, the spelling is not (0x8000 and 32768 are the
        # same constant). Bucket large magnitudes (a moved offset/size is
        # not "different logic"); keep small ones verbatim.
        v = int(num, 16) if num.lower().startswith("0x") else int(num)
        return ["IMM_LARGE" if abs(v) >= _LARGE_IMM else f"IMM:{v}"]

    # everything else : bucket registers, collapse a branch target to L
    s = re.sub(r"\bv\d+\b", "REG", out)
    if mnemonic.startswith(_BRANCH_PREFIXES):
        # the branch TARGET is the last operand (a +0xN/-0xN offset, a bare
        # number, or a pseudo-label). It is build-dependent, so collapse it to
        # one L token: control-flow KIND (if-eq / if-ge / goto / switch)
        # survives, distance does not. UNVERIFIED against a branch-bearing DEX
        # (the fixture has no branches) — a missed collapse only under-matches
        # (two methods that actually differ in loop size fall to STRONG/
        # PROBABLE by name), it never over-matches. Safe by construction.
        s = re.sub(r",\s*(?:[+-]?0x[0-9a-fA-F]+|[+-]?\d+|:\w+)\s*$", ", L", s)
        s = re.sub(r"\s+(?:[+-]?0x[0-9a-fA-F]+|[+-]?\d+|:\w+)\s*$", " L", s)
    s = re.sub(r"\s+", " ", s).strip()
    return [s] if s else []


def fingerprint_tokens(mnemonic_ops: list[tuple[str, str]]) -> str:
    """SHA-256 of a normalized instruction sequence. PURE.

    mnemonic_ops: [(mnemonic, operand_output), …] in program order. An empty
    or native-only sequence yields the fingerprint of an empty body (stable).
    """
    lines = []
    for mn, ops in mnemonic_ops:
        toks = normalize_instruction(mn, ops)
        lines.append(mn + (" " + " ".join(toks) if toks else ""))
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def callset_of(mnemonic_ops: list[tuple[str, str]]) -> frozenset[str]:
    """The set of call targets (CALL:…) a method uses — the STRONG-tier
    structural signal. PURE."""
    cs = set()
    for mn, ops in mnemonic_ops:
        for t in normalize_instruction(mn, ops):
            if t.startswith("CALL:"):
                cs.add(t)
    return frozenset(cs)


# ------------------------------------------------------------------ androguard glue
def fingerprint_method(method) -> tuple[str, list[str], int]:
    """Produce (fingerprint, sorted callset, instruction_count) for an
    androguard DalvikMethod. Uses androguard's OWN decoder (correct-by-
    construction) — never hand-rolls bytecode. Native methods (no body)
    return the empty-body fingerprint + a note-free 0 count."""
    try:
        ins = list(method.get_instructions() or [])
    except Exception:
        ins = []
    seq = [(i.get_name() or "", i.get_output() or "") for i in ins]
    return fingerprint_tokens(seq), sorted(callset_of(seq)), len(seq)


def dex_fingerprint_map(artifact: str) -> dict:
    """{M-key: {fp, name, class, callset, ins}} for every method in the
    artifact (APK or DEX). Requires androguard. M-key is a stable per-method
    identity within THIS artifact (class.name, disambiguated by order)."""
    from . import dexmapper
    from androguard.core.dex import DEX
    out: dict[str, dict] = {}
    seen: dict[str, int] = {}
    for dname, db in dexmapper._dex_bytes(artifact):
        d = DEX(db)
        for c in d.get_classes():
            cn = c.get_name().strip("L;").replace("/", ".")
            for m in c.get_methods():
                mname = m.get_name()
                acc = m.get_access_flags_string() or ""
                key_base = f"{cn}.{mname}"
                n = seen.get(key_base, 0)
                seen[key_base] = n + 1
                key = key_base if n == 0 else f"{key_base}#{n}"
                fp, cs, cnt = fingerprint_method(m)
                out[key] = {"fp": fp, "name": mname, "class": cn,
                            "callset": cs, "ins": cnt,
                            "native": "native" in acc, "dex": dname}
    return out


# ------------------------------------------------------------------ matching (PURE)
def match_cross_version(src: dict, dst: dict) -> list[dict]:
    """Match every dst method against the src fingerprint map.

    src / dst: {key: {fp, name, class, callset}} (from dex_fingerprint_map,
    or a synthetic equivalent for tests). Deterministic; returns one match
    dict per dst key, sorted by key. Status per the six-state contract:

      EXACT      dst fp == a src fp (identical normalized logic). A lone hit
                 is EXACT directly; a shared hit (identical logic in several
                 src methods) is EXACT only when the identity (class, name)
                 tiebreaks to a single one — never when the logic alone is
                 ambiguous. This is the only tier that may carry a validated
                 finding across versions WITHOUT re-validation.
      STRONG     fp differs but (same name AND identical callset) — very
                 likely the same method with a minor body change; must be
                 re-validated before a finding is promoted.
      AMBIGUOUS  dst fp matches >1 src method (src has a duplicate).
      CONFLICT   dst fp matches a src method that is ALSO the STRONG/EXACT
                 match of a DIFFERENT dst method (identity collision).
      PROBABLE   same name, callset differs (or no callset) — low trust.
      UNRESOLVED nothing close (neither fp nor name).

    Never merges PROBABLE as EXACT (the /360 invariant).
    """
    # index src by fp and by method NAME (not full class.name — across
    # versions the class is often renamed/refactored too, so name is the
    # honest cross-version signal; the callset is the STRONG/PROBABLE
    # tiebreak, and a name shared by several src methods is AMBIGUOUS)
    by_fp: dict[str, list[str]] = {}
    by_name: dict[str, list[str]] = {}
    for k, v in src.items():
        by_fp.setdefault(v["fp"], []).append(k)
        by_name.setdefault(v.get("name", ""), []).append(k)

    # pass 1: EXACT / AMBIGUOUS by fp (identity tiebreak); STRONG / PROBABLE
    # fallback by name
    provisional: dict[str, dict] = {}
    for dk in sorted(dst):
        d = dst[dk]
        fphits = by_fp.get(d["fp"], [])
        if len(fphits) == 1:
            sk = fphits[0]
            provisional[dk] = {"status": "EXACT", "src": sk,
                               "rule": "identical normalized fingerprint"}
        elif len(fphits) > 1:
            # shared fingerprint (identical logic in several src methods —
            # e.g. a battery of empty constructors / stubs). Tiebreak by
            # IDENTITY: same logic AND same (class, name) is the strongest
            # possible cross-version anchor; same logic but a different or
            # non-unique identity is NOT one — the fingerprint alone cannot
            # tell them apart.
            did = (d.get("class", ""), d.get("name", ""))
            same_id = [k for k in fphits
                       if (src[k].get("class", ""), src[k].get("name", "")) == did]
            if len(same_id) == 1:
                provisional[dk] = {
                    "status": "EXACT", "src": same_id[0],
                    "rule": f"identical fingerprint + identity "
                            f"(among {len(fphits)} same-logic methods)"}
            else:
                if same_id:
                    rule = (f"fingerprint matches {len(fphits)} src methods "
                            f"(same logic; identity shared by {len(same_id)} "
                            f"of them)")
                else:
                    rule = (f"fingerprint matches {len(fphits)} src methods "
                            f"(same logic; identity in none of them)")
                provisional[dk] = {"status": "AMBIGUOUS", "src": None,
                                   "candidates": sorted(fphits),
                                   "rule": rule}
        else:
            # no fp match -> name tier
            name_hits = by_name.get(d.get("name", ""), [])
            if len(name_hits) == 1:
                sk = name_hits[0]
                sc = src[sk]
                if sc.get("callset") and d.get("callset") \
                        and set(sc["callset"]) == set(d["callset"]):
                    provisional[dk] = {"status": "STRONG", "src": sk,
                                       "rule": "same name + identical callset "
                                               "(fingerprint differs — re-validate)"}
                else:
                    provisional[dk] = {"status": "PROBABLE", "src": sk,
                                       "rule": "same name only (low trust)"}
            elif len(name_hits) > 1:
                provisional[dk] = {"status": "AMBIGUOUS", "src": None,
                                   "candidates": sorted(name_hits),
                                   "rule": "name matches "
                                           f"{len(name_hits)} src methods"}
            else:
                provisional[dk] = {"status": "UNRESOLVED", "src": None,
                                   "rule": "no fingerprint or name match"}

    # pass 2: CONFLICT — a src method claimed by >1 dst method
    claimed: dict[str, list[str]] = {}
    for dk, p in provisional.items():
        if p.get("src"):
            claimed.setdefault(p["src"], []).append(dk)
    for sk, dks in claimed.items():
        if len(dks) > 1:
            for dk in dks:
                provisional[dk] = {
                    "status": "CONFLICT", "src": sk, "candidates": sorted(dks),
                    "rule": f"src {sk} is the match of {len(dks)} dst methods "
                            "(identity collision — not merged)"}

    # attach display info + sort
    out = []
    for dk in sorted(dst):
        p = provisional[dk]
        d = dst[dk]
        rec = {
            "dst": dk, "dst_name": d.get("name"), "dst_class": d.get("class"),
            "src": p.get("src"), "status": p["status"], "rule": p["rule"],
        }
        if p.get("candidates") is not None:
            rec["candidates"] = p["candidates"]
        out.append(rec)
    return out


# ------------------------------------------------------------------ render
def _tally(matches: list[dict]) -> dict:
    t = {s: 0 for s in STATES}
    for m in matches:
        t[m["status"]] += 1
    return t


def render_xmatch(matches: list[dict], sha_a: str, sha_b: str,
                  limit: int = 40) -> str:
    t = _tally(matches)
    head = (f"CROSS-VERSION MATCH  src sha[:8]={sha_a[:8]}  "
            f"dst sha[:8]={sha_b[:8]}")
    counts = "  ".join(f"{s}: {n}" for s, n in t.items() if n)
    lines = [head, f"{len(matches)} dst method(s)  {counts}"]
    # EXACT first (the ones that may carry findings), then the interesting
    order = {"EXACT": 0, "CONFLICT": 1, "STRONG": 2, "AMBIGUOUS": 3,
             "PROBABLE": 4, "UNRESOLVED": 5}
    shown = sorted(matches, key=lambda m: (order.get(m["status"], 9), m["dst"]))
    for m in shown[:limit]:
        tgt = m["src"] or ",".join(m.get("candidates", [])[:3]) or "—"
        lines.append(f"  {m['status']:<9} {m['dst']}  ->  {tgt}")
        lines.append(f"             {m['rule']}")
    if len(shown) > limit:
        lines.append(f"  … {len(shown) - limit} more (all UNRESOLVED unless "
                     f"stated)")
    lines.append("")
    lines.append("  only EXACT (identical logic) may carry a validated finding "
                 "across versions; STRONG/PROBABLE MUST be re-validated — "
                 "never merged as EXACT.")
    return "\n".join(lines)


# ------------------------------------------------------------------ engine
class XmatchEngine(core.Engine):
    """Cross-version match, as a job (two-APK parse is the heavy part).

    artifact = SRC path (the version a finding was validated on); the DST
    path arrives in params["dst"]. The session is keyed by the SRC sha; the
    rendered match board + the match list are stored so a later turn can
    read them back without re-parsing. Read-only with respect to both
    artifacts; runs under the watchdog budget (a pathological APK cannot
    hang the worker)."""

    spec = core.EngineSpec(name="xmatch",
                           description="cross-version method fingerprint match")

    def __init__(self, report_dir: str):
        self.report_dir = report_dir

    def can_run(self, artifact: str) -> bool:
        # NEVER auto-selected: xmatch needs TWO artifacts (src + --dst) and is
        # only reached via an explicit `/xmatch` command (which forces
        # engine="xmatch"). Returning True here (the old behavior) made it
        # catch any file no other engine accepted — e.g. a `.apk.bak` upload
        # mis-routed to xmatch and failed "no --dst" (real, 2026-10-02).
        return False

    def run(self, job: core.Job) -> core.EngineResult:
        import json as _json
        dst = (job.params or {}).get("dst")
        if not dst or not os.path.exists(dst):
            raise RuntimeError(
                "no --dst artifact (or it is missing) — /xmatch <src> <dst>")
        job.progress("intake", 0, "fingerprinting src")
        src = dex_fingerprint_map(job.artifact)
        job.checkpoint("src", {"sha256": core._sha256(job.artifact),
                               "methods": len(src)})
        job.progress("fingerprint", 60, "fingerprinting dst")
        dstmap = dex_fingerprint_map(dst)
        job.checkpoint("dst", {"sha256": core._sha256(dst),
                               "methods": len(dstmap)})
        job.progress("match", 90, "cross-version match")
        matches = match_cross_version(src, dstmap)
        sha_a = core._sha256(job.artifact)
        sha_b = core._sha256(dst)
        rendered = render_xmatch(matches, sha_a, sha_b, limit=200)
        # findings = the ones a human must NOT auto-promote (CONFLICT /
        # AMBIGUOUS) — the honest "re-validate here" list
        findings = [{
            "id": f"X{m['status'][0]}{i:02d}",
            "title": f"{m['dst']} -> {m['src'] or '(ambiguous)'}",
            "category": "cross-version-match",
            "evidenceLevel": "E2",
            "evidence": [{"level": "E2", "artifact": "classes.dex",
                          "detail": m["rule"]}],
            "confidence": "LOW" if m["status"] in ("CONFLICT", "AMBIGUOUS")
                          else "MEDIUM",
            "runtime": "UNKNOWN",
        } for i, m in enumerate(matches)
            if m["status"] in ("CONFLICT", "AMBIGUOUS")]
        os.makedirs(self.report_dir, exist_ok=True)
        ts = core.time.strftime("%Y%m%d-%H%M%S")
        rep = os.path.join(self.report_dir, f"xmatch-{ts}.json")
        _json.dump({"sha_a": sha_a, "sha_b": sha_b,
                    "src_methods": len(src), "dst_methods": len(dstmap),
                    "board": rendered, "matches": matches},
                   open(rep, "w"), indent=2)
        job.checkpoint("report", rep)
        job.progress("done", 100, f"{len(matches)} dst methods")
        return core.EngineResult(
            intake={"sha256": sha_a, "dst_sha256": sha_b,
                    "src_methods": len(src), "dst_methods": len(dstmap)},
            structural={"match_board": rendered, "matches": matches},
            findings=findings, report_md=rendered,
            outputs={"report": rep, "matches": len(matches),
                     **_tally(matches)})
