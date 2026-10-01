#!/usr/bin/env python3
"""vibe apk mod menu — authorized-APK analysis + patch PLANNING workbench.

Stages: intake -> detect (E1-E3 evidence) -> graph (callers/callees)
        -> plan (dry-run patch manifest, authorization-gated) -> report.

Authorization boundary (hard):
  * --intake/--detect/--graph/--report are READ-ONLY: safe for any APK
    (they only parse; nothing is modified, sent, or uploaded).
  * --plan writes a DRY-RUN patch manifest only (no APK bytes touched).
    It refuses without --authorized "I hold rights to modify <package>"
    (recorded in the plan) — the plan names the narrowest application-owned
    chokepoints with rollback metadata. Applying patches is OUT OF SCOPE
    for this slice by design (study note: offline patch -> rebuild -> sign
    -> runtime verify is a later, separately-gated stage).

Evidence model (study: studies/2026-10-01-apk-ad-removal.md):
  E1  SDK present (class/package/string/manifest)
  E2  manifest correlation (meta-data key for the SDK)
  E3  invoke relationship from an APPLICATION-OWNED class (call graph)
  E4  runtime-observed — NOT reachable by this static tool; findings that
      would need it stay at E3 with `runtime: UNKNOWN` until observed.
Falsification: every finding lists the counter-evidence that would weaken it
(dead class, no app caller, consent-gated only, debug-only path).

Dependency: androguard (DEX parsing). `--intake` works with stdlib only.
Usage:
  python3 tools/apkmod.py <apk> --menu
  python3 tools/apkmod.py <apk> --intake --detect --graph --report
  python3 tools/apkmod.py <apk> --plan --authorized "rights held: <evidence>"
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FP_DB = os.path.join(ROOT, "apk", "fingerprints.json")
OUT_DIR = os.path.join(ROOT, "apk-runs")

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

# ---------------------------------------------------------------- intake

def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _manifest_xml(apk_path: str) -> ET.Element:
    with zipfile.ZipFile(apk_path) as z:
        data = z.read("AndroidManifest.xml")
    # Binary XML — use androguard if present, else a best-effort aapt2 dump
    try:
        import warnings
        warnings.filterwarnings("ignore")
        from androguard.core.axml import AXMLPrinter
        xml_bytes = AXMLPrinter(data).get_xml()
        return ET.fromstring(xml_bytes)
    except ImportError:
        print("manifest parse needs androguard for binary XML "
              "(uv pip install androguard) — exit 3", file=sys.stderr)
        sys.exit(3)


def intake(apk_path: str) -> dict:
    root = _manifest_xml(apk_path)
    manifest_pkg = root.get("package", "")
    app = root.find("application")
    perms = [p.get(ANDROID_NS + "name") for p in root.iter("uses-permission")]
    uses_sdk = root.find("uses-sdk")
    meta = {}
    for m in root.iter("meta-data"):
        k, v = m.get(ANDROID_NS + "name"), m.get(ANDROID_NS + "value")
        if k:
            meta[k] = v
    entries = []
    dex, libs, assets = [], [], []
    with zipfile.ZipFile(apk_path) as z:
        for n in z.namelist():
            e = z.getinfo(n)
            entries.append({"name": n, "size": e.file_size})
            if re.fullmatch(r"classes\d*\.dex", n):
                dex.append(n)
            elif re.fullmatch(r"lib/[^/]+/.*\.so", n):
                libs.append(n)
            elif n.startswith("assets/"):
                assets.append(n)
    cert_digest = None
    try:
        import warnings
        warnings.filterwarnings("ignore")
        from androguard.core.apk import APK
        a = APK(apk_path)
        for c in a.get_certificates():
            f = c.fingerprint if hasattr(c, "fingerprint") else None
            if isinstance(f, dict):
                cert_digest = f.get("SHA-256")
            elif hasattr(c, "digest"):
                cert_digest = c.digest
            else:
                cert_digest = str(getattr(c, "subject", ""))[:60]
            break
    except Exception:
        pass
    return {
        "sha256": _sha256(apk_path),
        "size": os.path.getsize(apk_path),
        "package": manifest_pkg,
        "versionName": root.get(ANDROID_NS + "versionName"),
        "versionCode": root.get(ANDROID_NS + "versionCode"),
        "appClass": app.get(ANDROID_NS + "name") if app is not None else None,
        "minSdk": uses_sdk.get(ANDROID_NS + "minSdkVersion") if uses_sdk is not None else None,
        "targetSdk": uses_sdk.get(ANDROID_NS + "targetSdkVersion") if uses_sdk is not None else None,
        "permissions": perms,
        "metaData": meta,
        "activities": [a.get(ANDROID_NS + "name") for a in root.iter("activity")],
        "services": [s.get(ANDROID_NS + "name") for s in root.iter("service")],
        "receivers": [r.get(ANDROID_NS + "name") for r in root.iter("receiver")],
        "dexFiles": dex,
        "nativeLibs": libs,
        "assetsCount": len(assets),
        "entryCount": len(entries),
        "signingDigest": cert_digest,
    }


# ---------------------------------------------------------------- detect

def _dex_objects(apk_path: str):
    import warnings
    warnings.filterwarnings("ignore")
    from androguard.core.dex import DEX
    with zipfile.ZipFile(apk_path) as z:
        out = []
        for n in sorted(x for x in z.namelist() if re.fullmatch(r"classes\d*\.dex", x)):
            out.append((n, DEX(z.read(n))))
    return out


def _sdk_matches(cls_name: str, prefixes: dict) -> list[str]:
    """Class name (Lcom/foo/Bar;) vs reduced prefix DB (slash-form paths)."""
    path = cls_name.strip("L;").replace(".", "/") + "/"
    hits = []
    for sdk, pref in prefixes.items():
        for p in pref:
            if path.startswith(p):
                hits.append(sdk)
                break
    return hits


def detect(inv: dict, dexes: list, extra_fp: dict | None = None) -> list[dict]:
    fp = json.load(open(FP_DB, encoding="utf-8"))
    if extra_fp:
        for bucket in ("sdkClassPrefixes", "analyticsClassPrefixes"):
            for sdk, pref in (extra_fp.get(bucket) or {}).items():
                fp[bucket].setdefault(sdk, []).extend(pref)
        for k in ("manifestMetaKeys",):
            for sdk, keys in (extra_fp.get(k) or {}).items():
                fp[k].setdefault(sdk, []).extend(keys)
        for k in ("chokepointMethods", "adUiClassHints"):
            for x in (extra_fp.get(k) or []):
                if x not in fp[k]:
                    fp[k].append(x)
    app_pkg = (inv.get("package") or "").rstrip("/")
    findings: dict[str, dict] = {}

    def ensure(key: str, sdk: str, classification: str) -> dict:
        if key not in findings:
            findings[key] = {
                "sdk": sdk, "classification": classification,
                "evidence": [], "appCallers": [], "appCallees": [],
            }
        return findings[key]

    # E1: class-level presence
    all_classes = {}
    for dex_name, d in dexes:
        for c in d.get_classes():
            cn = c.get_name()
            all_classes[cn] = (dex_name, c)
    for cn in all_classes:
        for sdk in _sdk_matches(cn, fp["sdkClassPrefixes"]):
            dex_name, _ = all_classes[cn]
            f = ensure(f"{sdk}:{cn}", sdk, "ADVERTISING")
            f["evidence"].append({"level": "E1", "artifact": dex_name,
                                  "class": cn, "detail": "SDK class present in DEX"})
        for sdk in _sdk_matches(cn, fp["analyticsClassPrefixes"]):
            dex_name, _ = all_classes[cn]
            f = ensure(f"{sdk}:{cn}", sdk, "ANALYTICS")
            f["evidence"].append({"level": "E1", "artifact": dex_name,
                                  "class": cn, "detail": "analytics class present in DEX"})
        # generic ad-UI hint: match the CLASS NAME (last segment), so
        # any package's .../InterstitialAd, .../BannerView etc. is caught
        cls_name = cn.rstrip(";").rsplit("/", 1)[-1]
        if any(h.lower() in cls_name.lower() for h in fp.get("adUiClassHints", [])) \
                and not _sdk_matches(cn, fp["sdkClassPrefixes"]):
            f = ensure(f"AD-UI:{cn}", "AD-UI(generic)", "ADVERTISING")
            f["evidence"].append({"level": "E1", "artifact": all_classes[cn][0],
                                  "class": cn, "detail": "ad-UI class name hint (generic)"})

    # E2: manifest meta-data correlation
    for key, val in inv.get("metaData", {}).items():
        for sdk, keys in fp["manifestMetaKeys"].items():
            if any(key.startswith(k) or k in key for k in keys):
                f = ensure(f"{sdk}:manifest", sdk, "ADVERTISING")
                shown = val if len(str(val)) <= 12 else str(val)[:8] + "…"
                f["evidence"].append({"level": "E2", "artifact": "AndroidManifest.xml",
                                      "class": None,
                                      "detail": f"meta-data {key} = {shown}"})
        if any(key.startswith(k) or k.lower() in key.lower() for k in fp.get("consentKeys", [])):
            f = ensure(f"CONSENT:{key}", "CONSENT", "CONSENT")
            f["evidence"].append({"level": "E2", "artifact": "AndroidManifest.xml",
                                  "class": None, "detail": f"consent meta-data {key}"})

    # E3: application-owned call graph (app package invoking SDK chokepoints)
    for dex_name, d in dexes:
        for c in d.get_classes():
            cn = c.get_name().strip("L;").replace("/", ".")
            pkg = cn.rsplit(".", 1)[0]
            owned = pkg == app_pkg or pkg.startswith(app_pkg + ".")
            if not owned:
                continue
            for m in c.get_methods():
                mname_here = m.get_name()  # calling method name (plain)
                for ins in m.get_instructions():
                    nm = ins.get_name()
                    if not nm or not nm.startswith("invoke"):
                        continue
                    out = ins.get_output()
                    # out ~ "invoke-virtual {v0,v1}, Lcom/foo/Bar;->baz:(...)V"
                    target = out.split(",")[-1].strip()
                    if "->" not in target:
                        continue
                    tcls, rest = target.split("->", 1)
                    mname = rest.split("(", 1)[0]  # plain method name
                    tcls_plain = tcls.strip("L;").replace("/", ".")
                    if mname not in fp["chokepointMethods"]:
                        continue
                    tcls_slash = "L" + tcls_plain.replace(".", "/") + ";"
                    for sdk in _sdk_matches(tcls_slash, fp["sdkClassPrefixes"]):
                        f = ensure(f"{sdk}:{tcls_slash}", sdk, "ADVERTISING")
                        f["appCallers"].append({"artifact": dex_name, "class": cn,
                                                "method": mname_here,
                                                "invokes": f"{tcls_plain}.{mname}()"})
                        f["evidence"].append({"level": "E3", "artifact": dex_name,
                                              "class": cn, "method": mname_here,
                                              "detail": f"app {mname_here}() invokes "
                                                        f"{tcls_plain}.{mname}()"})
                    for sdk in _sdk_matches(tcls_slash, fp["analyticsClassPrefixes"]):
                        f = ensure(f"{sdk}:{tcls_slash}", sdk, "ANALYTICS")
                        f["appCallers"].append({"artifact": dex_name, "class": cn,
                                                "method": mname_here,
                                                "invokes": f"{tcls_plain}.{mname}()"})
                        f["evidence"].append({"level": "E3", "artifact": dex_name,
                                              "class": cn, "method": mname_here,
                                              "detail": f"app {mname_here}() invokes analytics "
                                                        f"{tcls_plain}.{mname}()"})

    # finalize: level = max evidence; falsification list
    out = []
    for i, (key, f) in enumerate(sorted(findings.items()), 1):
        levels = [e["level"] for e in f["evidence"]]
        level = max(levels, key=lambda x: int(x[1]))
        falsify = []
        if not f["appCallers"]:
            falsify.append("no application-owned caller found (SDK may be dead "
                           "code or invoked only via reflection/native)")
        if level in ("E1", "E2"):
            falsify.append("presence-only: feature flag or consent gate may "
                           "disable it at runtime (Runtime: UNKNOWN)")
        if "AD-UI" in f["sdk"]:
            falsify.append("generic UI hint: may belong to a different (non-ad) library")
        f.update({"id": f"FND-{i:03d}", "evidenceLevel": level,
                  "runtime": "UNKNOWN", "falsification": falsify or ["none identified"]})
        out.append(f)
    return out


# ---------------------------------------------------------------- graph

def graph(apk_path: str, findings: list[dict], dexes: list, inv: dict) -> None:
    fp = json.load(open(FP_DB, encoding="utf-8"))
    app_pkg = (inv.get("package") or "").rstrip("/")
    # build caller index for chokepoint methods
    print("\n=== CALL GRAPH (application-owned callers of SDK chokepoints) ===")
    for f in findings:
        if not f["appCallers"]:
            continue
        print(f"\n{f['id']} {f['sdk']} [{f['classification']}] level {f['evidenceLevel']}")
        for ev in f["evidence"]:
            loc = f"  E{ev['level'][1]} {ev['artifact']}"
            if ev.get("class"):
                loc += f"  {ev['class']}"
            if ev.get("method"):
                loc += f" .{ev['method']}()"
            loc += f"  — {ev['detail']}"
            print(loc)
        print("  callers:")
        for c in f["appCallers"]:
            line = f"    {c['class']}.{c['method']}()  (in {c['artifact']})"
            if c.get("invokes"):
                line += f"  ->  {c['invokes']}"
            print(line)
        print("  falsification:")
        for s in f["falsification"]:
            print(f"    - {s}")
    # chokepoint targets
    print("\n=== CHOKEPOINT TARGETS (narrowest patch candidates, by evidence level) ===")
    ranked = sorted([f for f in findings if f["appCallers"]],
                    key=lambda f: -int(f["evidenceLevel"][1]))
    for f in ranked:
        for c in f["appCallers"]:
            print(f"  {f['evidenceLevel']}  {c['class']}.{c['method']}()  "
                  f"-> {c.get('invokes', f['sdk'])}  [{f['id']}]")


# ---------------------------------------------------------------- plan

def plan(apk_path: str, findings: list[dict], inv: dict,
         authorized: str | None) -> dict:
    if not authorized:
        print("--plan requires --authorized '<rights statement>' (recorded in "
              "the plan). This is a DRY-RUN plan only; applying patches is a "
              "separately-gated later stage. (exit 3)", file=sys.stderr)
        sys.exit(3)
    candidates = []
    for f in findings:
        for c in f["appCallers"]:
            candidates.append({
                "id": f["id"], "sdk": f["sdk"], "classification": f["classification"],
                "evidenceLevel": f["evidenceLevel"],
                "chokepoint": f"{c['class']}.{c['method']}()",
                "artifact": c["artifact"],
                "action": "STUB-NOOP (recommended default: replace body with a "
                          "no-op return; keeps class/interface intact so no "
                          "ClassNotFoundException)",
                "alternatives": ["REMOVE-CALL (risk: dangling refs)",
                                 "DOMAIN-BLOCK (weak: SDK falls back / crashes)",
                                 "UI-HIDE (banner containers only — cosmetic)"],
                "rollback": "snapshot of classes*.dex before patch + patch "
                            "manifest (revert = restore snapshot + resign)",
                "risk": "LOW" if f["evidenceLevel"] == "E3" else "REVIEW",
                "runtimeVerify": "launch -> exercise screen -> confirm no ad "
                                 "requests in network log, no ANR/crash",
            })
    plan_doc = {
        "planVersion": "0.1.0",
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": {"sha256": inv["sha256"], "package": inv["package"],
                   "versionName": inv["versionName"], "versionCode": inv["versionCode"]},
        "authorization": {"statement": authorized,
                          "note": "recorded at planning time; re-verify before applying"},
        "scope": "DRY-RUN ONLY — no APK bytes modified by this tool",
        "candidates": candidates,
        "excluded": {"runtimeOnly": "E4 findings need runtime observation first",
                     "noCaller": "E1/E2-only findings need a caller or a UI-hide"},
        "stagesLater": ["apply (smali/dex edit) -> structural check -> rebuild -> "
                        "sign -> install -> runtime verify -> before/after report"],
    }
    return plan_doc


# ---------------------------------------------------------------- report

def report(apk_path: str, inv: dict, findings: list[dict], plan_doc: dict | None,
           out_dir: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    path = os.path.join(out_dir, f"apk-report-{ts}.md")
    lines = ["# vibe apk report card", ""]
    lines.append(f"- generated: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
    lines.append(f"- artifact: `{os.path.basename(apk_path)}`  sha256 `{inv['sha256']}`")
    lines.append(f"- package: {inv['package']} v{inv['versionName']} (code {inv['versionCode']})  "
                 f"minSdk {inv['minSdk']} / targetSdk {inv['targetSdk']}")
    lines.append(f"- dex: {', '.join(inv['dexFiles'])}   native: {len(inv['nativeLibs'])}   "
                 f"assets: {inv['assetsCount']}   signing: {(inv['signingDigest'] or 'n/a')[:32]}…")
    lines.append(f"- permissions: {', '.join(inv['permissions']) or 'none'}")
    lines.append("")
    by_class: dict[str, int] = {}
    for f in findings:
        by_class[f["classification"]] = by_class.get(f["classification"], 0) + 1
    lines.append(f"**findings: {len(findings)}**  " +
                 "  ".join(f"{k}={v}" for k, v in sorted(by_class.items())))
    lines.append("")
    lines.append("| id | sdk | class | level | runtime | app callers | weakest falsification |")
    lines.append("|----|-----|-------|-------|---------|-------------|----------------------|")
    for f in sorted(findings, key=lambda x: x["id"]):
        lines.append(f"| {f['id']} | {f['sdk']} | {f['classification']} | "
                     f"{f['evidenceLevel']} | {f['runtime']} | {len(f['appCallers'])} | "
                     f"{f['falsification'][0][:60]} |")
    lines.append("")
    if plan_doc:
        lines.append(f"## Patch plan (DRY-RUN) — authorized: {plan_doc['authorization']['statement']}")
        lines.append("")
        for c in plan_doc["candidates"]:
            lines.append(f"- **{c['chokepoint']}** → {c['sdk']} [{c['id']}]  "
                         f"level {c['evidenceLevel']}  action: {c['action'][:40]}  risk {c['risk']}")
        lines.append("")
    lines.append("Static analysis ceiling: E3 (app-owned caller). `runtime: UNKNOWN` "
                 "until observed — presence ≠ execution. Applying patches is a "
                 "separately-gated later stage (see studies/2026-10-01-apk-ad-removal.md).")
    open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    return path


# ---------------------------------------------------------------- menu

MENU = """
=================  vibe · APK MOD MENU  =================
 1  INTAKE      — identity, manifest, inventory, signing
 2  DETECT      — ad/analytics/consent findings (E1-E3 evidence)
 3  GRAPH       — call graph: app-owned callers of chokepoints
 4  PLAN        — DRY-RUN patch plan (needs --authorized)
 5  REPORT      — write markdown report card to apk-runs/
 0  QUIT
================================================================
"""


def run_menu(apk_path: str, authorized: str | None, out_dir: str,
             extra_fp: dict | None = None):
    inv = None
    findings = None
    dexes = None
    plan_doc = None
    while True:
        print(MENU)
        if inv is None:
            print("[1 INTAKE]")
            inv = intake(apk_path)
            print(json.dumps({k: inv[k] for k in
                              ("sha256", "package", "versionName", "minSdk", "targetSdk")},
                             indent=2))
            print(f"perms={inv['permissions']} dex={inv['dexFiles']} "
                  f"libs={len(inv['nativeLibs'])} entries={inv['entryCount']}")
        choice = input("menu> ").strip().lower()
        try:
            if choice == "0" or choice == "q":
                break
            elif choice == "1":
                print(json.dumps(inv, indent=2, default=str))
            elif choice in ("2", "d"):
                if dexes is None:
                    dexes = _dex_objects(apk_path)
                if findings is None:
                    findings = detect(inv, dexes, extra_fp)
                for f in findings:
                    print(f"{f['id']} {f['sdk']:<16} {f['classification']:<13} "
                          f"lvl={f['evidenceLevel']} callers={len(f['appCallers'])} "
                          f"runtime={f['runtime']}")
            elif choice in ("3", "g"):
                if findings is None:
                    dexes = dexes or _dex_objects(apk_path)
                    findings = detect(inv, dexes, extra_fp)
                if dexes is None:
                    dexes = _dex_objects(apk_path)
                graph(apk_path, findings, dexes, inv)
            elif choice == "4":
                if findings is None:
                    dexes = dexes or _dex_objects(apk_path)
                    findings = detect(inv, dexes, extra_fp)
                plan_doc = plan(apk_path, findings, inv, authorized)
                os.makedirs(out_dir, exist_ok=True)
                pp = os.path.join(out_dir, "patch-plan.json")
                json.dump(plan_doc, open(pp, "w"), indent=2)
                print(f"plan (DRY-RUN) written: {pp}  candidates={len(plan_doc['candidates'])}")
                for c in plan_doc["candidates"]:
                    print(f"  {c['chokepoint']} -> {c['sdk']} [{c['id']}] risk {c['risk']}")
            elif choice == "5":
                if findings is None:
                    dexes = dexes or _dex_objects(apk_path)
                    findings = detect(inv, dexes, extra_fp)
                p = report(apk_path, inv, findings, plan_doc, out_dir)
                print(f"report: {p}")
            else:
                print("unknown choice")
        except SystemExit as e:
            print(f"[stopped: {e}]")
            break
        except Exception as e:  # noqa: BLE001 — menu keeps going
            print(f"[error: {type(e).__name__}: {e}]")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("apk")
    ap.add_argument("--menu", action="store_true", help="interactive mod menu")
    ap.add_argument("--intake", action="store_true")
    ap.add_argument("--detect", action="store_true")
    ap.add_argument("--graph", action="store_true")
    ap.add_argument("--plan", action="store_true")
    ap.add_argument("--authorized", default=None,
                    help="rights statement recorded in the plan (required for --plan)")
    ap.add_argument("--report", action="store_true")
    ap.add_argument("--fingerprints", default=None,
                    help="extra reduced fingerprint DB (JSON) for proprietary/obfuscated "
                         "SDKs; merges into apk/fingerprints.json (same schema)")
    ap.add_argument("--out-dir", default=OUT_DIR)
    args = ap.parse_args()

    extra_fp = None
    if args.fingerprints:
        extra_fp = json.load(open(args.fingerprints, encoding="utf-8"))

    if not os.path.exists(args.apk):
        print(f"apk not found: {args.apk} (exit 3)", file=sys.stderr)
        sys.exit(3)
    if args.menu:
        run_menu(args.apk, args.authorized, args.out_dir, extra_fp)
        return

    inv = intake(args.apk)
    if args.intake and not (args.detect or args.graph or args.report or args.plan):
        print(json.dumps(inv, indent=2, default=str))
    else:
        print(json.dumps({k: inv[k] for k in ("sha256", "package", "versionName",
                                              "minSdk", "targetSdk", "permissions")}, indent=2))
    findings = dexes = plan_doc = None
    if args.detect or args.graph or args.report or args.plan:
        dexes = _dex_objects(args.apk)
        findings = detect(inv, dexes, extra_fp)
        for f in findings:
            print(f"{f['id']} {f['sdk']:<16} {f['classification']:<13} "
                  f"lvl={f['evidenceLevel']} callers={len(f['appCallers'])} "
                  f"runtime={f['runtime']}")
    if args.graph and findings is not None:
        graph(args.apk, findings, dexes, inv)
    if args.plan:
        plan_doc = plan(args.apk, findings or [], inv, args.authorized)
        os.makedirs(args.out_dir, exist_ok=True)
        json.dump(plan_doc, open(os.path.join(args.out_dir, "patch-plan.json"), "w"), indent=2)
        print(f"plan (DRY-RUN) written to {args.out_dir}/patch-plan.json "
              f"({len(plan_doc['candidates'])} candidates)")
    if args.report:
        print("report:", report(args.apk, inv, findings or [], plan_doc, args.out_dir))


if __name__ == "__main__":
    main()
