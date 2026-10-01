# VibeBot — P14: hybrid-app JS-layer detection (deterministic, pure core)
#
# lupoxyz technique #4: a "hybrid" APK carries its REAL business logic in a
# web layer (a WebView + bundled JS/HTML), not in DEX. The classic case is a
# uni-app build: the app's logic lives in
#   assets/apps/_UNI_<appid>/www/app-service.js
# and a "premium" gate is a JS object in that file (e.g.
#   vip: { code: "..." }) — patchable at the JS layer, invisible to a
# DEX-only pass. Other hybrids: Cordova/PhoneGap (www/index.html +
# cordova.js), React Native (assets/index.android.bundle), Flutter
# (assets/flutter_assets/*, logic in .so, not JS).
#
# /360 discipline: this reports WHERE the logic layer is + which framework
# signature matched (E1 = container-entry fact, E2 = a DEX-side bridge/use
# fact). It is a ROUTING signal — "don't deep-dive the DEX for this, look in
# the JS" — not a claim about what the app does. NOT OBSERVED for a framework
# we didn't see is reported as such, never guessed.
#
# Pure core (scan_names / classify) needs NO androguard and takes a list of
# ZIP entry names + optional DEX-side signals -> fully unit-testable on
# synthetic name lists (positive control) AND the real fixture (negative).
from __future__ import annotations

import zipfile
import os

GRAPH = dict

# Framework signature table. Matched as a SUBSTRING against lower-cased ZIP
# entry paths (deterministic, no regex — a path either contains the marker or
# it doesn't). These are documented, public framework layout facts (uni-app /
# Cordova / RN / Flutter release layouts), not reverse-engineered constants.
FRAMEWORKS: list[dict] = [
    {"name": "uniapp",
     "labels": ["uni-app", "DCloud uni-app"],
     "entry_markers": ["assets/apps/_uni_", "www/app-service.js"],
     "js_entry": "app-service.js",
     "note": "uni-app (DCloud): logic in assets/apps/_UNI_*/www/ — "
             "app-service.js is the main bundle; app-view.js renders; "
             "static/ holds assets"},
    {"name": "cordova",
     "labels": ["Apache Cordova", "PhoneGap"],
     "entry_markers": ["www/cordova.js", "www/index.html", "cordova_plugins.js"],
     "js_entry": "index.html",
     "note": "Cordova/PhoneGap: logic in www/ + plugins/; cordova.js is the "
             "JS<->native bridge"},
    {"name": "reactnative",
     "labels": ["React Native"],
     "entry_markers": ["assets/index.android.bundle",
                       "assets/index.android.bundle.meta"],
     "js_entry": "index.android.bundle",
     "note": "React Native: the JS bundle (often obfuscated/minified) is "
             "assets/index.android.bundle; the DEX side is a thin shell"},
    {"name": "flutter",
     "labels": ["Flutter"],
     "entry_markers": ["assets/flutter_assets/"],
     "js_entry": None,
     "note": "Flutter: logic compiles to native (libapp.so) — NOT a JS "
             "layer; the hybrid patch target is the .so, not www/"},
]


def classify(names: list[str]) -> dict:
    """Match framework signatures against ZIP entry names (PURE).

    names: iterable of entry paths (e.g. a.ZipFile.namelist()). Returns
    {"detected": {framework_name: [matched marker entries...]},
     "js_entries": [paths that look like a JS/HTML logic layer],
     "assets_count": int}. A framework is detected when >=1 of its
    entry_markers appears in some name.
    """
    lower = [n for n in names]
    llower = [n.lower() for n in names]
    detected: dict[str, list[str]] = {}
    for fw in FRAMEWORKS:
        hits: list[str] = []
        for m in fw["entry_markers"]:
            ml = m.lower()
            for raw, lo in zip(lower, llower):
                if ml in lo:
                    if raw not in hits:
                        hits.append(raw)
        if hits:
            detected[fw["name"]] = hits

    # JS/HTML logic-layer entries (the patch target for hybrid apps)
    js_entries = []
    for raw, lo in zip(lower, llower):
        if lo.startswith("assets/") and (
                lo.endswith(".js") or lo.endswith(".html")
                or lo.endswith(".bundle") or "app-service" in lo
                or "app-view" in lo):
            js_entries.append(raw)
    return {"detected": detected, "js_entries": js_entries,
            "assets_count": sum(1 for n in lower if n.startswith("assets/"))}


def scan_artifact(artifact: str) -> dict:
    """APK / bare .dex / directory -> hybrid-layer signature (androguard-free;
    zip + optional DEX-side bridge signals).

    Returns {"kind", "frameworks": {name: {"markers": [...], "js_entry": str,
    "note": str}}, "js_entries": [...], "webview_used": bool,
    "jsinterface": [dex-side @JavascriptInterface / addJavascriptInterface
    class refs], "assets": [...]}.
    """
    out: dict = {"kind": None, "frameworks": {}, "js_entries": [],
                 "webview_used": False, "jsinterface": [], "assets": []}
    if not os.path.exists(artifact):
        out["error"] = f"not found: {artifact}"
        return out

    if artifact.lower().endswith((".apk", ".apkx", ".zip")):
        out["kind"] = "zip"
        try:
            with zipfile.ZipFile(artifact) as z:
                names = z.namelist()
        except zipfile.BadZipFile as e:
            out["error"] = f"bad zip: {e}"
            return out
        c = classify(names)
        out["assets"] = sorted(n for n in names if n.startswith("assets/"))
        out["js_entries"] = c["js_entries"]
        for name, hits in c["detected"].items():
            fw = next(f for f in FRAMEWORKS if f["name"] == name)
            out["frameworks"][name] = {"markers": hits[:12],
                                       "js_entry": fw["js_entry"],
                                       "note": fw["note"]}
    elif artifact.lower().endswith(".dex"):
        out["kind"] = "dex"
        out["note"] = "bare .dex has no asset layer — hybrid layer NOT " \
                      "OBSERVABLE from this artifact (run the /apk path)"
        return out
    elif os.path.isdir(artifact):
        # exploded APK directory: walk it
        out["kind"] = "dir"
        names = []
        for root, _dirs, files in os.walk(artifact):
            for f in files:
                full = os.path.join(root, f)
                names.append(os.path.relpath(full, artifact))
        c = classify(names)
        out["assets"] = sorted(n for n in names if n.startswith("assets/"))
        out["js_entries"] = c["js_entries"]
        for name, hits in c["detected"].items():
            fw = next(f for f in FRAMEWORKS if f["name"] == name)
            out["frameworks"][name] = {"markers": hits[:12],
                                       "js_entry": fw["js_entry"],
                                       "note": fw["note"]}
    else:
        out["kind"] = "unknown"
        out["error"] = "unsupported artifact type for asset scan"
        return out

    # DEX-side signals (when the artifact is an APK, read the call graph)
    if out["kind"] == "zip" and _apk_has_dex(artifact):
        try:
            from . import dexmapper
            for dname, db in dexmapper._dex_bytes(artifact):
                m = dexmapper.map_dex(db, dname, "")
                for call in m["calls"]:
                    tc = call["targetClass"]
                    if tc.startswith("android.webkit."):
                        out["webview_used"] = True
                    if tc in ("android.webkit.WebView",
                              "android.webkit.WebView$JsInterface") or \
                       "JsInterface" in tc:
                        if call["targetMethod"] == "addJavascriptInterface":
                            out["webview_used"] = True
                    if "JsInterface" in tc and call["targetMethod"] != "<init>":
                        out["jsinterface"].append(
                            f"{call['caller']}.{call['callerMethod']} -> "
                            f"{tc}.{call['targetMethod']}")
        except Exception as e:  # DEX-side is best-effort
            out["dex_signals_error"] = f"{type(e).__name__}: {e}"
        # dedupe + sort
        out["jsinterface"] = sorted(set(out["jsinterface"]))[:20]
    return out


def _apk_has_dex(artifact: str) -> bool:
    try:
        with zipfile.ZipFile(artifact) as z:
            return any(n.endswith(".dex") for n in z.namelist())
    except Exception:
        return False


def render_hybrid(sig: dict, sha: str) -> str:
    """/apk overview section: where the logic layer is."""
    lines = ["HYBRID / JS LAYER"]
    if sig.get("error"):
        lines.append(f"  {sig['error']} (NOT OBSERVED)")
        return "\n".join(lines)
    if sig.get("kind") == "dex":
        lines.append(f"  {sig.get('note', 'not observable')}")
        return "\n".join(lines)
    fws = sig.get("frameworks") or {}
    if fws:
        for name in sorted(fws):
            fw = fws[name]
            lines.append(f"  [E1] framework {name} — {fw.get('note','')}")
            lines.append(f"         markers: {', '.join(fw['markers'][:5])}"
                         f"{' …' if len(fw['markers']) > 5 else ''}")
            if fw.get("js_entry"):
                lines.append(f"         JS entry: {fw['js_entry']}")
        js = sig.get("js_entries") or []
        if js:
            shown = ", ".join(os.path.basename(j) for j in js[:6])
            more = f" …+{len(js) - 6}" if len(js) > 6 else ""
            lines.append(f"  [E1] JS layer entries: {shown}{more}")
        lines.append("  => the app's logic is in the WEB layer, not the DEX. "
                     "Patch the JS entry, not the smali.")
    else:
        assets = sig.get("assets") or []
        if assets:
            lines.append(f"  [E1] {len(assets)} asset file(s) — no known "
                         "hybrid-framework signature matched "
                         "(webview-only? custom web layer?)")
        else:
            lines.append("  [E1] no asset layer / no JS hybrid signature "
                         "(native-only APK)")
    # DEX-side bridge signals
    if sig.get("webview_used"):
        lines.append("  [E2] DEX side references android.webkit.WebView — "
                     "a WebView is instantiated (web content is rendered)")
    ji = sig.get("jsinterface") or []
    if ji:
        lines.append(f"  [E2] JS<->native bridge: {len(ji)} "
                     "addJavascriptInterface / JsInterface use(s):")
        for r in ji[:5]:
            lines.append(f"     {r}")
    if not fws and not (sig.get("assets")) and sig.get("kind") == "zip":
        lines.append("  NOT OBSERVED: no assets/ in this APK")
    return "\n".join(lines)
