#!/usr/bin/env python3
"""Validate the vibe knowledge payload: JSON shape, probe/axis integrity,
manifest sha256 (v1 and v2), and documented-axis coverage.

Run: python3 tools/validate.py   (offline — no network)

schemaVersion 2 notes:
  * multi-turn probes carry a structured "turns" list (no more 'turnN:' strings)
  * manifest v2 authenticates every verdict-controlling artifact, not just the
    payload (artifacts: {relpath: sha256})
  * every axis documented in method/*.md must have >=1 probe (coverage gate)
"""
import hashlib
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _sha(path: str) -> str:
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def probe_texts(p: dict) -> list[str]:
    """All fillable text of a probe (single template or multi-turn list)."""
    if p.get("turns"):
        return [t.get("template", "") for t in p["turns"]]
    return [p.get("template", "")]


def main() -> int:
    errors = []

    probes_path = os.path.join(ROOT, "probes", "probes.json")
    manifest_path = os.path.join(ROOT, "manifest.json")

    probes = json.load(open(probes_path))
    manifest = json.load(open(manifest_path))

    # 1. manifest authenticity (v2: every artifact; v1: single payload sha)
    artifacts = manifest.get("artifacts")
    if artifacts:
        for rel, declared in artifacts.items():
            path = os.path.join(ROOT, rel)
            if not os.path.exists(path):
                errors.append(f"manifest artifact missing on disk: {rel}")
                continue
            actual = _sha(path)
            if actual != declared.lower():
                errors.append(f"manifest artifact hash mismatch: {rel} "
                              f"({declared[:12]}… != {actual[:12]}…)")
    else:
        if manifest.get("payload") != "probes/probes.json":
            errors.append(f"manifest payload path wrong: {manifest.get('payload')}")
        actual = _sha(probes_path)
        if actual != manifest.get("sha256"):
            errors.append(f"manifest sha256 mismatch: {manifest.get('sha256')} != {actual}")

    # 2. schema gate fields
    for field in ("knowledgeVersion", "schemaVersion", "minimumAppVersion"):
        if field not in manifest:
            errors.append(f"manifest missing {field}")
    if not (manifest.get("artifacts") or manifest.get("sha256")):
        errors.append("manifest has neither v1 sha256 nor v2 artifacts")
    if probes.get("schemaVersion") != manifest.get("schemaVersion"):
        errors.append("schemaVersion differs between manifest and payload")

    # 3. probe integrity
    seen = set()
    probes_list = probes.get("probes", [])
    if not probes_list:
        errors.append("no probes")
    for p in probes_list:
        pid = p.get("id")
        if not pid:
            errors.append("probe without id")
            continue
        if pid in seen:
            errors.append(f"duplicate probe id {pid}")
        seen.add(pid)
        if not (1 <= int(p.get("family", 0)) <= 9):
            errors.append(f"{pid}: family out of range 1..9")
        texts = probe_texts(p)
        if not texts or not any(t.strip() for t in texts):
            errors.append(f"{pid}: missing template/turns text")
        for ax in p.get("axes", []):
            m = re.fullmatch(r"([AB])(\d+)", ax)
            ok = bool(m) and (m.group(1) == "A" and 1 <= int(m.group(2)) <= 23
                              or m.group(1) == "B" and 1 <= int(m.group(2)) <= 8)
            if not ok:
                errors.append(f"{pid}: malformed axis {ax}")
        # must be parameterized (reduced), not a hardcoded payload
        joined = " ".join(texts)
        if "{" not in joined and p["family"] != 3:
            errors.append(f"{pid}: no {placeholder} anywhere (must be reduced/synthetic)"
                          .replace("{placeholder}", "placeholder"))
        # structured multi-turn: no legacy 'turnN:' string parsing anywhere
        if re.search(r"\bturn\d+\s*:", joined, re.I):
            errors.append(f"{pid}: legacy 'turnN:' template — use structured 'turns'")

    # 4. controls present
    if not probes.get("controls"):
        errors.append("missing controls")

    # 5. every method doc exists for families 1..9
    method_dir = os.path.join(ROOT, "method")
    for i in range(1, 10):
        files = [f for f in os.listdir(method_dir) if f.startswith(f"{i:02d}-")]
        if not files:
            errors.append(f"method doc missing for family {i}")

    # 6. documented-axis coverage: every axis defined in method/*.md has >=1 probe
    doc_axes = set()
    for f in os.listdir(method_dir):
        if f.endswith(".md"):
            txt = open(os.path.join(method_dir, f), encoding="utf-8").read()
            doc_axes |= set(re.findall(r"\b([AB]\d{1,2})\b", txt))
    probe_axes = {ax for p in probes_list for ax in p.get("axes", [])}
    # only enforce axes that appear in an explicit 'Axis A##' / 'A## —' doc line
    # (bare mentions in prose are too noisy)
    defined = set()
    for f in os.listdir(method_dir):
        if f.endswith(".md"):
            txt = open(os.path.join(method_dir, f), encoding="utf-8").read()
            defined |= set(re.findall(r"\*\*([AB]\d{1,2})\s+[a-z]", txt))  # "- **A11 stance**:"
            defined |= set(re.findall(r"\bAxis\s+([AB]\d{1,2})\b", txt))
    missing_cov = sorted(defined - probe_axes)
    if missing_cov:
        errors.append("documented axes without any probe: " + ", ".join(missing_cov))

    if errors:
        print("vibe validate: FAILED")
        for e in errors:
            print("  -", e)
        return 1
    print(f"vibe validate: OK — {len(probes_list)} probes, "
          f"{len(probes.get('controls', []))} controls, "
          f"{len(probe_axes)} axes covered, "
          f"{'manifest v2 (' + str(len(artifacts)) + ' artifacts)' if artifacts else 'manifest v1'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
