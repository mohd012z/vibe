"""Frida oracle GATING (lupoxyz study backlog #9) — pure, stdlib-only.

Design note: `studies/2026-10-02-frida-oracle-gating-spec.md`.

This module is the *gate* in front of a future Frida runtime call — NOT the
call itself. There is deliberately no Frida import here: the whole point is
that an oracle call is OFF by default and cannot fire by accident, so the
gating logic is implementable and unit-testable today (CI passes with no
Frida), and the runtime worker wires it in later.

The safety rationale (from the study, verbatim intent):
    "a totally-wrong address faults and is contained; a SLIGHTLY-wrong one
     runs real code mid-function and corrupts live state that no restart
     undoes."
A wrong call that crashes is cheap; a wrong call that runs is not. Hence the
default is DO NOT CALL AT ALL, and the only callable targets are NAMED
EXPORTS (never a raw/absolute address).
"""
from __future__ import annotations

import os
import re

# off-by-default switch (mirrors the reference GHIDRA_MCP_ORACLE_CALL=1)
ENV_ORACLE_CALL = "VIBE_ORACLE_CALL"

# the two oracle modes (from the study)
MODE_CALL_ONLY = "call-only"      # call the original to confirm/refute a claim
MODE_DIFFERENTIAL = "differential"  # call original + reimpl, diff over inputs

# named-export shapes (JNI underscore form / Module.getExportByName symbol).
# A raw target is a hex address (0x..) or a bare integer — NEVER callable.
_HEX_RE = re.compile(r"^(0[xX][0-9a-fA-F]+|\d+)$")
_SYMBOL_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")


def oracle_enabled(flag_value: str | None = None) -> bool:
    """Is an oracle call explicitly opted in? OFF unless flag is truthy.

    `flag_value` (when not None) is an explicit override (e.g. a job param);
    otherwise read the env var. Truthy = "1", "true", "yes", "on" (case-insens).
    """
    raw = flag_value if flag_value is not None else os.environ.get(ENV_ORACLE_CALL)
    return raw is not None and str(raw).strip().lower() in ("1", "true", "yes", "on")


def classify_target(target: str) -> str:
    """Classify an oracle target: 'named_export' | 'raw_address' | 'unknown'.

    raw_address = a hex (0x..) or bare-integer target — the dangerous case the
    gate exists to refuse. named_export = a symbol name (identifier, optionally
    dotted/JNI-underscored). Everything else is 'unknown' (also refused).
    """
    t = (target or "").strip()
    if not t:
        return "unknown"
    if _HEX_RE.match(t):
        return "raw_address"
    if _SYMBOL_RE.match(t):
        return "named_export"
    return "unknown"


def decide(target: str, mode: str = MODE_CALL_ONLY,
           reference: str | None = None,
           flag_value: str | None = None) -> dict:
    """The gating decision for one oracle call. Applies the spec's rules:

    1. OFF by default (no explicit opt-in -> refused, NOT OBSERVED).
    2. Named exports only (raw address / unknown target -> refused).
    3. Differential additionally requires a named reference (else degrade to
       call-only when the caller allows, else refuse).
    4. Fail closed: a refusal is a terminal NOT OBSERVED, never a warning.

    Returns {allowed: bool, mode: str, reason: str, target_class: str}.
    """
    if mode not in (MODE_CALL_ONLY, MODE_DIFFERENTIAL):
        return {"allowed": False, "mode": mode, "reason": f"unknown mode '{mode}'",
                "target_class": "unknown"}
    # rule 1: off by default
    if not oracle_enabled(flag_value):
        return {"allowed": False, "mode": mode,
                "reason": f"oracle is OFF by default (set {ENV_ORACLE_CALL}=1 to "
                          "opt in) — NOT OBSERVED, not a silent call",
                "target_class": classify_target(target)}
    # rule 2: named export only
    tclass = classify_target(target)
    if tclass == "raw_address":
        return {"allowed": False, "mode": mode,
                "reason": "refusing raw/absolute address target — only NAMED "
                          "exports are callable (a slightly-wrong address "
                          "corrupts live state)",
                "target_class": tclass}
    if tclass == "unknown":
        return {"allowed": False, "mode": mode,
                "reason": "target is not a recognized named export — refused",
                "target_class": tclass}
    # rule 3: differential needs a named reference on the reimpl side
    if mode == MODE_DIFFERENTIAL:
        rclass = classify_target(reference or "")
        if rclass != "named_export":
            return {"allowed": False, "mode": mode,
                    "reason": "differential oracle needs a NAMED reference "
                              "implementation target (original AND reimpl "
                              "must both be named exports)",
                    "target_class": tclass}
    return {"allowed": True, "mode": mode,
            "reason": "ok (explicit opt-in; named export" +
                      ("; named reference" if mode == MODE_DIFFERENTIAL else "") + ")",
            "target_class": tclass}


def diff_outputs(original: list, reimpl: list, inputs: list) -> dict:
    """Pure differential diff over an input vector.

    `original`/`reimpl` are the output lists for the same `inputs`. Returns
    {equivalent, n, mismatches:[(i, in, orig, reimpl)]}. No Frida, no target —
    this is what the differential mode asserts after the (gated) calls happen.
    """
    n = len(original) if original is not None else 0
    mismatches = []
    for i, (a, b) in enumerate(zip(original or [], reimpl or [])):
        if a != b:
            ins = inputs[i] if inputs is not None and i < len(inputs) else None
            mismatches.append((i, ins, a, b))
    equivalent = (len(original or []) == len(reimpl or [])
                  and not mismatches and n > 0)
    return {"equivalent": equivalent, "n": n, "mismatches": mismatches}
