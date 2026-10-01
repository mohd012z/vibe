# VibeBot — P3: Evidence + Claim model  (deterministic, pure)
#
# The /360 correction #2: "Separate Claim from Evidence". Tool output is
# NEVER truth. An observation is EVIDENCE (E1..E5 by what it can establish);
# a statement built on evidence is a CLAIM with a state machine:
#
#     PROPOSED -> SUPPORTED -> REPRODUCED -> VALIDATED
#                     \--> CONFLICTED -> UNRESOLVED / REJECTED
#
# and a CodeTransparent category (FACT / OBSERVATION / INFERENCE /
# ASSUMPTION / UNKNOWN / CONFLICT). This module derives claims PURELY from
# the Vibe IR graph (+ optional DEX byte-integrity reports), so it is
# testable without androguard, and every claim traces to an entity + an
# evidence level (the "/why" chain). No AI is involved — this is the
# deterministic bottom of the stack per "less AI at the bottom".

GRAPH = dict
CLAIM = "claim"

# ------------------------------------------------------------------ E-levels
# What each observation CAN establish (and, importantly, what it cannot).
EVIDENCE_STRENGTH = {
    "E1": "manifest / DEX structure (reconstructed) — establishes declared "
          "structure; does NOT establish behavior",
    "E2": "DEX byte/instruction (const-string, invoke, access flag) — "
          "establishes the instruction exists; does NOT establish execution",
    "E3": "static cross-reference from a native/ELF provider (Radare) — "
          "establishes a reference; does NOT establish execution",
    "E4": "independent second-engine cross-reference (Ghidra) — establishes "
          "corroboration of a location",
    "E5": "runtime observation (Frida) — establishes behavior was observed in "
          "ONE test run; NOT OBSERVED elsewhere is NOT impossible",
}

# CodeTransparent statement categories (correction #14).
CATEGORIES = ("FACT", "OBSERVATION", "INFERENCE", "ASSUMPTION", "UNKNOWN",
              "CONFLICT")

# Claim state machine (correction #2).
CLAIM_STATES = ("PROPOSED", "SUPPORTED", "REPRODUCED", "VALIDATED",
                "CONFLICTED", "UNRESOLVED", "REJECTED")
TRANSITIONS: dict[str, frozenset[str]] = {
    "PROPOSED": frozenset({"SUPPORTED", "REJECTED", "UNRESOLVED"}),
    "SUPPORTED": frozenset({"REPRODUCED", "CONFLICTED", "REJECTED", "VALIDATED"}),
    "REPRODUCED": frozenset({"VALIDATED", "CONFLICTED", "REJECTED"}),
    "VALIDATED": frozenset({"CONFLICTED"}),   # a fact can be invalidated
    "CONFLICTED": frozenset({"UNRESOLVED", "REJECTED", "VALIDATED"}),
    "UNRESOLVED": frozenset({"SUPPORTED", "REJECTED"}),
    "REJECTED": frozenset(),
}


def transition(state: str, to: str):
    """Return the new state if the move is legal, else None.

    This is the enforcement of "Found" != "proved" and "PROPOSED" !=
    "VALIDATED": you cannot skip a state. Illegal moves return None so a
    caller can treat them as a no-op + log, never a silent state jump.
    """
    return to if to in TRANSITIONS.get(state, frozenset()) else None


def is_reachable(state: str) -> bool:
    return state in CLAIM_STATES


# ------------------------------------------------------------------ Claim
def _claim(cid, statement, *, category, state, evidence,
           contradicts=None, note=None) -> dict:
    return {
        "id": cid,
        "statement": statement,
        "category": category,
        "state": state,
        "evidence": evidence,          # list of {level, ref, detail}
        "contradicting": contradicts or [],
        "note": note,
    }


def _ev(level: str, ref: str, detail: str) -> dict:
    return {"level": level, "ref": ref, "detail": detail}


# ------------------------------------------------------------------ derive
def build_claims(graph: dict, dex_reports: list[dict] | None = None) -> list[dict]:
    """Derive the claim set PURELY from the graph (+ DEX integrity).

    Deterministic: same graph + same dex_reports -> same claim list, same
    ids. That is what makes it re-checkable (REPRODUCED) and CI-stable.
    """
    claims: list[dict] = []
    n = 0

    def _next() -> str:
        nonlocal n
        n += 1
        return f"C{n}"

    nodes = graph.get("nodes", {})
    counts = graph.get("counts", {})
    package = graph.get("package", "?")
    art = nodes.get("artifact", [{}])
    art_path = art[0].get("path") if art else None

    # ---- identity (E1, deterministic => VALIDATED) --------------------
    claims.append(_claim(
        _next(),
        f"artifact is an Android APK — package '{package}', "
        f"{counts.get('class', 0)} classes, {counts.get('method', 0)} methods, "
        f"{counts.get('component', 0)} components, {counts.get('native', 0)} native",
        category="FACT", state="VALIDATED",
        evidence=[_ev("E1", "A1", "manifest + DEX inventory, reproducible per SHA")],
        note=f"file: {art_path}" if art_path else None))

    # ---- DEX byte integrity (E2 byte-level) ---------------------------
    dex_v = dex_c = 0
    for rep in (dex_reports or []):
        ok = bool(rep.get("valid"))
        fails = [k for k in ("magic_ok", "version_ok", "size_ok",
                             "checksum_ok", "sha1_ok")
                 if rep.get(k) is False]
        if ok:
            dex_v += 1
            claims.append(_claim(
                _next(), f"{rep.get('dex', '?')} DEX header is valid "
                         "(magic, version, size, adler32, sha1)",
                category="FACT", state="VALIDATED",
                evidence=[_ev("E2", rep.get("dex", "?"),
                              "byte-level header integrity check")]))
        else:
            dex_c += 1
            claims.append(_claim(
                _next(), f"{rep.get('dex', '?')} DEX header is INVALID",
                category="CONFLICT", state="CONFLICTED",
                evidence=[_ev("E2", rep.get("dex", "?"),
                              "; ".join(fails) or "unknown failure")],
                contradicts=[_ev("E2", rep.get("dex", "?"),
                                 "expected a well-formed DEX header")]))

    # ---- manifest-declared components (E1 => VALIDATED) ---------------
    for comp in nodes.get("component", []):
        claims.append(_claim(
            _next(), f"{comp['id']} is a manifest-declared {comp['kind']} "
                     f"('{comp['name']}')",
            category="FACT", state="VALIDATED",
            evidence=[_ev("E1", comp["id"], "AndroidManifest.xml declaration")]))

    # ---- string usage (E2) --------------------------------------------
    referenced = 0
    orphan_ids = []
    for s in nodes.get("string", []):
        refs = s.get("refs", [])
        if refs:
            referenced += 1
            state = "REPRODUCED" if len({(r.get("class"), r.get("method"))
                                         for r in refs}) >= 2 else "SUPPORTED"
            claims.append(_claim(
                _next(), f"{s['id']} '{s['value']}' is referenced by "
                         f"{len(refs)} method(s)",
                category="OBSERVATION", state=state,
                evidence=[_ev("E2", f"{r.get('class')}.{r.get('method')}",
                              "const-string instruction") for r in refs[:5]]))
        else:
            orphan_ids.append(s["id"])
    if orphan_ids:
        claims.append(_claim(
            _next(), f"{len(orphan_ids)} string(s) are in the string table "
                     f"but not statically referenced (e.g. {orphan_ids[:4]})",
            category="OBSERVATION", state="PROPOSED",
            evidence=[_ev("E2", "string-table", "present, no static ref found")],
            note="absence of a static ref is NOT proof of non-use — could be "
                 "referenced dynamically (NOT OBSERVED != IMPOSSIBLE)"))

    # ---- JNI boundary (E2) with honest runtime gap ---------------------
    for nm in nodes.get("native", []):
        claims.append(_claim(
            _next(), f"{nm['id']} {nm['class']}.{nm['method']} is declared "
                     f"native (JNI boundary)",
            category="FACT", state="SUPPORTED",
            evidence=[_ev("E2", nm["id"], "method access flag 'native'")],
            note="backing .so function NOT OBSERVED (no native provider "
                 "installed) — NOT OBSERVED != IMPOSSIBLE"))

    # ---- call graph (E2 aggregate) -------------------------------------
    call_count = counts.get("call", 0)
    if call_count:
        targets = {c.get("targetClass") for c in graph.get("calls", [])}
        claims.append(_claim(
            _next(), f"call graph has {call_count} invoke edge(s) across "
                     f"{len(targets)} target class(es)",
            category="OBSERVATION", state="SUPPORTED",
            evidence=[_ev("E2", "invoke-*", "DEX invoke instructions decoded")]))

    # ---- coverage summary (deterministic => VALIDATED) ----------------
    comp_count = len(nodes.get("component", []))
    n_native = len(nodes.get("native", []))
    claims.append(_claim(
        _next(),
        f"coverage — identity VALIDATED · dex-integrity {dex_v}valid/"
        f"{dex_c}conflict · components {comp_count} · strings {referenced}"
        f" referenced · native {n_native} · runtime NOT TESTED",
        category="OBSERVATION", state="VALIDATED",
        evidence=[_ev("E1", "A1", "deterministic summary of the claim set")],
        note="this is a COVERAGE statement, not a confidence percentage"))
    return claims


# ------------------------------------------------------------------ /why
def why(claims: list[dict], claim_id: str, sha: str) -> str:
    """CodeTransparent trace for one claim: CLAIM -> EVIDENCE -> REF ->
    entity -> ARTIFACT, with the E-level meaning made explicit. This is the
    'tap Why?' chain from correction #14."""
    c = next((x for x in claims if x["id"] == claim_id), None)
    if c is None:
        avail = ", ".join(x["id"] for x in claims[:12])
        return f"no claim {claim_id}. Available: {avail}…"
    nxt = " -> ".join(sorted(TRANSITIONS.get(c["state"], frozenset()))
                      or ["(terminal)"])
    lines = [f"WHY {c['id']}  sha[:8]={sha[:8]}",
             f"  statement: {c['statement']}",
             f"  category:  {c['category']}",
             f"  state:     {c['state']}   (can transition to: {nxt})",
             "  evidence:"]
    for e in c["evidence"]:
        lines.append(f"    [E{e['level'][1:]}] {e['ref']}  — {e['detail']}")
        lines.append(f"        establishes: {EVIDENCE_STRENGTH[e['level']]}")
    for e in c["contradicting"]:
        lines.append(f"  contradicts: [E{e['level'][1:]}] {e['ref']} — {e['detail']}")
    if c.get("note"):
        lines.append(f"  note: {c['note']}")
    lines.append(f"  -> REF {c['evidence'][0]['ref'] if c['evidence'] else '?'} "
                 f"-> ARTIFACT A1")
    return "\n".join(lines)


# ------------------------------------------------------------------ render
def render_claims(claims: list[dict], sha: str) -> str:
    """The evidence board: grouped by state, one compact line each."""
    order = ["VALIDATED", "REPRODUCED", "SUPPORTED", "PROPOSED",
             "CONFLICTED", "UNRESOLVED", "REJECTED"]
    lines = [f"EVIDENCE BOARD  (sha[:8]={sha[:8]})",
             f"{len(claims)} claims  " +
             "  ".join(f"{s}: {sum(1 for c in claims if c['state'] == s)}"
                       for s in order
                       if any(c["state"] == s for c in claims))]
    for s in order:
        group = [c for c in claims if c["state"] == s]
        if not group:
            continue
        lines.append(f"\n[{s}]")
        for c in group:
            ev = c["evidence"][0] if c["evidence"] else None
            tag = f"[{ev['level']}]" if ev else "[—]"
            lines.append(f"  {c['id']} {tag} {c['category']:<10} "
                         f"{c['statement'][:70]}")
    lines.append("\n/why <C-id>  to trace any claim to its evidence + bytes")
    return "\n".join(lines)
