#!/usr/bin/env python3
"""Validate the vibe knowledge payload: JSON shape, probe/axis integrity, manifest sha256.

Run: python3 tools/validate.py   (offline — no network)
"""
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main() -> int:
    errors = []

    probes_path = os.path.join(ROOT, "probes", "probes.json")
    manifest_path = os.path.join(ROOT, "manifest.json")

    probes = json.load(open(probes_path))
    manifest = json.load(open(manifest_path))

    # 1. manifest sha256 matches the payload (the verify-before-load gate)
    actual = hashlib.sha256(open(probes_path, "rb").read()).hexdigest()
    if actual != manifest.get("sha256"):
        errors.append(f"manifest sha256 mismatch: {manifest.get('sha256')} != {actual}")
    if manifest.get("payload") != "probes/probes.json":
        errors.append(f"manifest payload path wrong: {manifest.get('payload')}")

    # 2. schema gate fields present
    for field in ("knowledgeVersion", "schemaVersion", "minimumAppVersion", "sha256"):
        if field not in manifest:
            errors.append(f"manifest missing {field}")
    if probes.get("schemaVersion") != manifest.get("schemaVersion"):
        errors.append("schemaVersion differs between manifest and payload")

    # 3. probe integrity: ids unique, axes reference A##/C##, families in 1..8
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
        if not (1 <= int(p.get("family", 0)) <= 8):
            errors.append(f"{pid}: family out of range 1..8")
        if not p.get("template"):
            errors.append(f"{pid}: missing template")
        for ax in p.get("axes", []):
            ok = ax.startswith("A") and ax[1:].isdigit() and 1 <= int(ax[1:]) <= 23
            if not ok:
                errors.append(f"{pid}: malformed axis {ax}")
        # template must be parameterized (reduced), not a hardcoded payload
        if "{" not in p.get("template", "") and p["family"] != 3:
            errors.append(f"{pid}: template has no placeholder (must be reduced/synthetic)")

    # 4. controls present
    if not probes.get("controls"):
        errors.append("missing controls")

    # 5. every method doc exists for families 1..8
    method_dir = os.path.join(ROOT, "method")
    for i in range(1, 9):
        files = [f for f in os.listdir(method_dir) if f.startswith(f"{i:02d}-")]
        if not files:
            errors.append(f"method doc missing for family {i}")

    if errors:
        print("vibe validate: FAILED")
        for e in errors:
            print("  -", e)
        return 1
    print(f"vibe validate: OK — {len(probes_list)} probes, "
          f"{len(probes.get('controls', []))} controls, "
          f"sha256={actual[:12]}…")
    return 0


if __name__ == "__main__":
    sys.exit(main())
