# VibeBot — P11: Falsifier (deterministic mechanical refutation)
#
# /360 stage: "challenges its own conclusions" -> VALIDATOR + FALSIFIER.
# After claims are derived from the graph, this module RE-CHECKS each
# falsifiable fact against an INDEPENDENT reading of the same graph — never
# the same field the fact came from. A contradiction is a finding, not a
# silent fix: the affected claim is moved to CONFLICTED (the only legal
# transition out of VALIDATED) with the contradiction recorded, and the
# board shows a FALSIFIED section.
#
# Why this is not circular:
#   * claim "call graph has M edges" uses counts["call"]; the falsifier
#     recounts len(graph["calls"]) — a DIFFERENT field.
#   * native nodes are collected in build_graph's FIRST DEX pass (access
#     flags) while method nodes come from dexmapper's SECOND pass; they can
#     diverge. The falsifier cross-checks the two.
#   * string refs carry (class, method); the falsifier verifies each points
#     at a real method node.
# No AI, no androguard — pure Python over the stored graph dict, so it is
# unit-testable on a synthetic graph and runs in CI with the toolchain absent.
#
# Severity:
#   tier1  hard contradiction — the stated fact is wrong (-> CONFLICTED)
#   note   soft/uncertain — flagged, not refuted (stays as-is, advisory)

GRAPH = dict
FINDING = "finding"

from .claims import TRANSITIONS  # noqa: E402  (state machine is the contract)

TIER1 = "tier1"
NOTE = "note"


def _finding(claim_id, kind, expected, actual, severity, detail):
    return {"claim_id": claim_id, "kind": kind, "expected": expected,
            "actual": actual, "severity": severity, "detail": detail}


# ------------------------------------------------------------------ indexes
def _method_keys(graph):
    """Set of (class, method) that exist as real method nodes."""
    return {(m.get("class"), m.get("name"))
            for m in graph.get("nodes", {}).get("method", [])}


def _native_by_key(graph):
    return {(n.get("class"), n.get("method"))
            for n in graph.get("nodes", {}).get("native", [])}


# ------------------------------------------------------------------ graph
def falsify_graph(graph):
    """Independent invariant checks over the graph itself.

    Returns a list of findings. These are NOT tied to one claim; they are
    artifact-level contradictions (claim_id is None). A non-empty result
    means the graph is internally inconsistent, so ANY claim derived from it
    is suspect.
    """
    findings = []
    nodes = graph.get("nodes", {})
    counts = graph.get("counts", {})
    calls = graph.get("calls", [])
    method_keys = _method_keys(graph)
    class_keys = {m.get("class") for m in nodes.get("method", [])}

    # ---- counts vs. actual node lists (stale-count corruption) ----------
    for node_type, count_key in (("class", "class"), ("method", "method"),
                                 ("string", "string"), ("native", "native"),
                                 ("component", "component")):
        stated = counts.get(count_key)
        actual = len(nodes.get(node_type, []))
        if stated is not None and stated != actual:
            findings.append(_finding(
                None, f"count:{node_type}", stated, actual, TIER1,
                f"counts['{count_key}']={stated} but {len(nodes.get(node_type, []))} "
                f"{node_type} nodes exist"))

    # ---- call-edge count (claims cite counts['call']) -------------------
    call_stated = counts.get("call")
    if call_stated is not None and call_stated != len(calls):
        findings.append(_finding(
            None, "count:call", call_stated, len(calls), TIER1,
            f"counts['call']={call_stated} but {len(calls)} call edges exist"))

    # ---- call edges reference real classes -----------------------------
    for i, c in enumerate(calls):
        for role in ("sourceClass", "targetClass"):
            cls = c.get(role)
            if cls and cls not in class_keys and not _is_external(cls):
                findings.append(_finding(
                    None, f"call:{role}", "known class", cls, NOTE,
                    f"call[{i}] {role} '{cls}' is not a method-bearing class "
                    "(may be an external/framework class — advisory)"))

    # ---- native nodes must be real, native-flagged methods --------------
    native_keys = _native_by_key(graph)
    method_native = {(m.get("class"), m.get("name"))
                     for m in nodes.get("method", []) if m.get("native")}
    for k in sorted(native_keys - method_native):
        if k in method_keys:
            findings.append(_finding(
                None, "native:flag", "native=True", "native=False/absent", TIER1,
                f"native node {k[0]}.{k[1]} is listed native but its method "
                f"node is not flagged native (two DEX passes diverged)"))
        else:
            findings.append(_finding(
                None, "native:missing", "method node exists", "absent", TIER1,
                f"native node {k[0]}.{k[1]} has no corresponding method node"))

    # ---- string refs must point at real methods -------------------------
    dangling = 0
    for s in nodes.get("string", []):
        for r in s.get("refs", []):
            if (r.get("class"), r.get("method")) not in method_keys:
                dangling += 1
    if dangling:
        findings.append(_finding(
            None, "string:dangling_ref", 0, dangling, TIER1,
            f"{dangling} string ref(s) point at (class, method) pairs that "
            f"are not real method nodes"))

    return findings


def _is_external(cls):
    """Rough external/framework heuristic: no dot (single-segment) or a
    known platform root. Advisory only — never refutes on its own."""
    return (cls is not None and ("." not in cls or cls.startswith(("android.",
            "java.", "javax.", "kotlin."))))


# ------------------------------------------------------------------ claims
def falsify_claims(claims, graph):
    """Re-check each falsifiable claim's stated fact against an independent
    reading of the graph. Returns findings (claim_id set, not None)."""
    findings = []
    nodes = graph.get("nodes", {})
    method_keys = _method_keys(graph)
    calls = graph.get("calls", [])

    for c in claims:
        stmt = c.get("statement", "")

        # ---- "call graph has M invoke edge(s) across T target class(es)"
        if stmt.startswith("call graph has"):
            m = _first_int(stmt, after="has ")
            t = _first_int(stmt, after="across ")
            if m is not None and m != len(calls):
                findings.append(_finding(
                    c["id"], "call:edges", m, len(calls), TIER1,
                    f"claim says {m} edges; recount of calls list = {len(calls)}"))
            if t is not None:
                actual_targets = {x.get("targetClass") for x in calls}
                if t != len(actual_targets):
                    findings.append(_finding(
                        c["id"], "call:targets", t, len(actual_targets), TIER1,
                        f"claim says {t} target classes; recount = {len(actual_targets)}"))

        # ---- "Sx '...' is referenced by N method(s)"
        if " is referenced by " in stmt and stmt.startswith("S"):
            n = _first_int(stmt, after="by ")
            if n is not None:
                sid = stmt.split(" ", 1)[0]
                s = next((x for x in nodes.get("string", []) if x["id"] == sid), None)
                if s is None:
                    findings.append(_finding(
                        c["id"], "string:missing", sid, "absent", TIER1,
                        f"claim cites string {sid} which is not in the graph"))
                else:
                    actual_n = len(s.get("refs", []))
                    if n != actual_n:
                        findings.append(_finding(
                            c["id"], "string:refs", n, actual_n, TIER1,
                            f"claim says {n} refs; string node has {actual_n}"))
                    for r in s.get("refs", []):
                        if (r.get("class"), r.get("method")) not in method_keys:
                            findings.append(_finding(
                                c["id"], "string:dangling_ref", "real method",
                                f"{r.get('class')}.{r.get('method')}", TIER1,
                                f"ref {r.get('class')}.{r.get('method')} is not a "
                                f"real method node"))

        # ---- "Nx Class.method is declared native (JNI boundary)"
        if " is declared native" in stmt and stmt.startswith("N"):
            nid = stmt.split(" ", 1)[0]
            cn = next((x for x in nodes.get("native", []) if x["id"] == nid), None)
            if cn is None:
                findings.append(_finding(
                    c["id"], "native:missing", nid, "absent", TIER1,
                    f"claim cites native {nid} which is not in the graph"))
            else:
                if (cn.get("class"), cn.get("method")) not in method_keys:
                    findings.append(_finding(
                        c["id"], "native:no_method", "method exists", "absent",
                        TIER1,
                        f"{cn.get('class')}.{cn.get('method')} has no method node"))

    return findings


def _first_int(stmt, after=""):
    """First integer appearing after the `after` substring, or None."""
    idx = stmt.find(after)
    if idx < 0:
        return None
    rest = stmt[idx + len(after):]
    for tok in rest.replace("(", " ").replace(")", " ").split():
        t = tok.strip(".,;")
        if t.isdigit():
            return int(t)
    return None


# ------------------------------------------------------------------ apply
def apply_falsifications(claims, findings):
    """Move each claim with a tier1 finding to CONFLICTED (the only legal
    transition out of VALIDATED/SUPPORTED) and attach the contradiction as
    evidence. Returns the (possibly new) claims list. NOTE-severity findings
    do not change state. Claims already CONFLICTED/REJECTED are left alone.
    Deterministic; mutates a shallow copy, never the caller's dicts' state
    in place (new dicts returned for changed claims)."""
    out = []
    for c in claims:
        hits = [f for f in findings
                if f["claim_id"] == c["id"] and f["severity"] == TIER1]
        if hits and c["state"] not in ("CONFLICTED", "REJECTED"):
            # Route through the claim state machine — the falsifier may
            # CHALLENGE, never silently skip a state. CONFLICTED is legal
            # from VALIDATED/SUPPORTED/REPRODUCED; a bare PROPOSED claim
            # that is contradicted is REJECTED (legal from PROPOSED).
            to_state = ("CONFLICTED"
                        if "CONFLICTED" in TRANSITIONS.get(c["state"], frozenset())
                        else "REJECTED")
            new = dict(c)
            new["state"] = to_state
            new["contradicting"] = list(c.get("contradicting", [])) + [
                {"level": "F1", "ref": "falsifier",
                 "detail": f"{f['kind']}: expected {f['expected']}, "
                           f"got {f['actual']} — {f['detail']}"}
                for f in hits]
            out.append(new)
        else:
            out.append(c)
    return out


# ------------------------------------------------------------------ render
def render_falsifications(findings, sha):
    """Compact board section: the FALSIFIED block (or the honest 'clean' line)."""
    tier1 = [f for f in findings if f["severity"] == TIER1]
    notes = [f for f in findings if f["severity"] == NOTE]
    lines = [f"FALSIFIER  (sha[:8]={sha[:8]})"]
    if not findings:
        lines.append("  no contradictions — every falsifiable claim re-checked "
                     "clean against an independent reading of the graph")
        return "\n".join(lines)
    if tier1:
        lines.append(f"[REFUTED — {len(tier1)} hard contradiction(s)]")
        for f in tier1:
            cid = f["claim_id"] or "(graph)"
            lines.append(f"  {cid} {f['kind']}: expected {f['expected']}, "
                         f"got {f['actual']}")
            lines.append(f"        {f['detail']}")
    if notes:
        lines.append(f"[advisory — {len(notes)} note(s)]")
        for f in notes:
            cid = f["claim_id"] or "(graph)"
            lines.append(f"  {cid} {f['kind']}: {f['detail']}")
    lines.append("  a REFUTED claim is CONFLICTED, not deleted — resolution is "
                 "a separate step (the falsifier flags; it does not choose)")
    return "\n".join(lines)
