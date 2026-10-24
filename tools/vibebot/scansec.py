"""vibebot.scansec — manifest security + secrets entropy + TLS surface scan.

The gap-split study (studies/2026-10-24-scansec-surface.md, Anam 2026-10-24
"what else need to add to analyze any apk to find all those thing") showed
the reasoning engine was complete but five coverage surfaces were missing;
this module is the first two of them:

  * manifest security — exported components, intent-filter actions, deep
    links (autoVerify), allowBackup / debuggable / cleartext-traffic /
    networkSecurityConfig, exported providers
  * secrets — Shannon-entropy + well-known public format patterns over DEX
    strings, manifest meta-data values and ZIP entry names (AWS keys,
    GitHub tokens, Slack tokens, Google API keys, private-key blocks, …)
    Values are MASKED in every report (first 4 chars + length) — a secret
    must not be echoed into a stored session that outlives the artifact.
  * TLS surface — custom X509TrustManager subclasses, OkHttp
    CertificatePinner references, WebView addJavascriptInterface call
    sites (E2), networkSecurityConfig presence. This is the static side of
    the Flutter-TLS-bypass finding (m4kr0x): pinning/bypass machinery that
    matters for traffic interception.

Evidence discipline (repo invariant): every line is E1 (presence in this
artifact) or E2 (a call site / manifest correlation); `runtime: UNKNOWN`
until observed. NOT OBSERVED is a labeled gap, never an absence claim.

Architecture: PURE functions over plain dicts/strings (unit-testable with
synthetic inputs, no androguard) + thin androguard glue (manifest via
apkmod._manifest_xml, DEX strings + superclasses via androguard's own
decoder — the proven path, never hand-rolled DEX parsing) + ScanSecEngine.
"""

from __future__ import annotations

import math
import os
import re
import zipfile
import xml.etree.ElementTree as ET

from . import core

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

# ------------------------------------------------------------------ secrets

# Well-known public key/token FORMATS (shape, not any vendor's private
# scheme). Short, additive, mechanism-only — same discipline as
# apk/fingerprints.json.
SECRET_PATTERNS: list[tuple[str, str, str]] = [
    # (name, regex, severity)
    ("AWS access key ID", r"AKIA[0-9A-Z]{16}", "HIGH"),
    ("GitHub token (classic/pat)",
     r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,}", "HIGH"),
    ("Slack token", r"xox[baprs]-[A-Za-z0-9-]{10,}", "HIGH"),
    ("Google API key", r"AIza[0-9A-Za-z_-]{35}", "MED"),
    ("OpenAI-style secret key", r"\bsk-[A-Za-z0-9]{20,}", "MED"),
    ("Private key block", r"BEGIN (?:RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY", "HIGH"),
    ("JWT", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}", "MED"),
]
SECRET_RE = [(n, re.compile(p), s) for n, p, s in SECRET_PATTERNS]

ENTROPY_MIN = 4.0      # shannon bits/char; mixed-case+digit secrets sit ~4.0-4.7
ENTROPY_LEN_MIN = 16   # shorter strings are names/IDs, not secret-shaped
ENTROPY_TOP_N = 15     # bounded report


def shannon_entropy(s: str) -> float:
    """Shannon entropy in bits/char (pure, stdlib). Empty -> 0.0."""
    if not s:
        return 0.0
    n = len(s)
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def mask(value: str) -> str:
    """Mask a secret for reports: first 4 chars + length, never the whole."""
    if len(value) <= 8:
        return f"{value[:2]}…(len {len(value)})"
    return f"{value[:4]}…(len {len(value)})"


def _is_dex_type_or_descriptor(s: str) -> bool:
    """DEX type refs (Lcom/foo/Bar;) and method descriptors (xxx(I)V) are
    structural strings — exclude them from the entropy census so the report
    is about data, not bytecode vocabulary."""
    return (s.startswith("L") and s.endswith(";") and "/" in s) or \
           (s.endswith(")") and "(" in s)


def find_secret_patterns(text: str, source: str,
                         out: list[dict], cap: int = 40) -> list[dict]:
    """Pattern hits over one string (pure). Appends masked findings to `out`
    and returns the same list (bounded by `cap` to keep a 60 MB string
    table from producing an unbounded report)."""
    for name, rx, sev in SECRET_RE:
        m = rx.search(text)
        if m and len(out) < cap:
            out.append({
                "kind": "pattern", "pattern": name, "severity": sev,
                "source": source, "value": mask(m.group(0)),
                "entropy": round(shannon_entropy(m.group(0)), 3),
                "level": "E1",
            })
    return out


def entropy_census(strings: list[str], source: str) -> list[dict]:
    """High-entropy string census (pure). Returns top-N by entropy, masked.
    DEX type/method structural strings are excluded (see helper)."""
    scored = []
    for s in strings:
        if len(s) < ENTROPY_LEN_MIN or _is_dex_type_or_descriptor(s):
            continue
        e = shannon_entropy(s)
        if e >= ENTROPY_MIN:
            scored.append((e, s, source))
    scored.sort(key=lambda t: (-t[0], t[2]))
    return [{
        "kind": "entropy", "pattern": f"shannon≥{ENTROPY_MIN}", "severity": "MED",
        "source": src, "value": mask(s), "entropy": round(e, 3), "level": "E1",
    } for e, s, src in scored[:ENTROPY_TOP_N]]


def scan_strings(strings: list[tuple[str, str]]) -> list[dict]:
    """strings = [(value, source)] (pure). Patterns + entropy, deduped by
    (pattern, masked value, source)."""
    out: list[dict] = []
    for val, src in strings:
        find_secret_patterns(val, src, out)
    out.extend(entropy_census([v for v, _ in strings], "dex/strings"))
    seen = set()
    uniq = []
    for f in out:
        k = (f["kind"], f["pattern"], f["value"], f["source"])
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    return uniq


# ----------------------------------------------------------- manifest scan

_COMPONENTS = ("activity", "service", "receiver", "provider")


def _attr(el: ET.Element, name: str) -> str | None:
    return el.get(ANDROID_NS + name)


def _intent_filters(el: ET.Element) -> list[dict]:
    """Each intent-filter under a component: its actions + data schemes."""
    out = []
    for f in el.findall("intent-filter"):
        acts = [a.get(ANDROID_NS + "name") for a in f.findall("action")
                if a.get(ANDROID_NS + "name")]
        data = []
        for d in f.findall("data"):
            scheme = _attr(d, "scheme")
            host = _attr(d, "host")
            auto = _attr(f, "autoVerify")
            data.append({"scheme": scheme, "host": host,
                         "autoVerify": auto or (d.get(ANDROID_NS + "autoVerify"))})
        out.append({"actions": acts, "data": data})
    return out


def scan_manifest(root: ET.Element, zip_names: list[str] | None = None) -> dict:
    """Pure manifest security scan over the parsed (text) manifest XML.

    `zip_names` (the APK's ZIP entry list, optional) lets the scan say
    whether a referenced networkSecurityConfig file actually ships in the
    APK — a reference to a missing file is itself a finding."""
    app = root.find("application")
    if app is None:
        app = ET.Element("application")
    zip_set = set(zip_names or [])

    exported: list[dict] = []
    implicit_exported: list[dict] = []
    deep_links: list[dict] = []
    providers: list[dict] = []
    flags: dict[str, str | None] = {
        "debuggable": _attr(app, "debuggable"),
        "allowBackup": _attr(app, "allowBackup"),
        "usesCleartextTraffic": _attr(app, "usesCleartextTraffic"),
        "hasBackupRules": _attr(app, "hasBackupRules") or
                          _attr(app, "fullBackupContent"),
    }
    nsc = _attr(app, "networkSecurityConfig")
    nsc_status = "NOT REFERENCED"
    if nsc:
        # res reference like @xml/network_security_config -> res/xml/…
        name = nsc.lstrip("@")
        candidates = {f"res/xml/{name}", f"res/xml/{os.path.basename(name)}"}
        nsc_status = "present in APK" if candidates & zip_set else \
                     f"REFERENCED BUT NOT FOUND in APK ({nsc})"

    for kind in _COMPONENTS:
        for el in app.findall(kind):
            cname = _attr(el, "name") or "?"
            ifs = _intent_filters(el)
            exported_attr = _attr(el, "exported")
            has_if = any(ifs)
            if exported_attr == "true":
                exported.append({"kind": kind, "name": cname,
                                 "actions": [a for f in ifs for a in f["actions"]],
                                 "basis": "explicit"})
            elif exported_attr != "false" and has_if:
                # no explicit exported + has intent-filter: pre-Android 12
                # this was implicitly exported (and on 31+ the build should
                # have been forced to say). Report, don't assume the value.
                implicit_exported.append({
                    "kind": kind, "name": cname,
                    "actions": [a for f in ifs for a in f["actions"]],
                    "basis": "implicit (intent-filter, no android:exported)"})
            for f in ifs:
                for d in f["data"]:
                    if d["scheme"] or d["host"]:
                        deep_links.append({
                            "kind": kind, "name": cname, "scheme": d["scheme"],
                            "host": d["host"], "autoVerify": bool(d["autoVerify"]),
                        })
            if kind == "provider":
                providers.append({
                    "name": cname,
                    "exported": exported_attr,
                    "grantUriPermissions": _attr(el, "grantUriPermissions"),
                    "readPermission": _attr(el, "readPermission"),
                    "unreadPermission": _attr(el, "unreadPermission"),
                })

    return {
        "exported": exported,
        "implicitExported": implicit_exported,
        "deepLinks": deep_links,
        "providers": providers,
        "flags": flags,
        "networkSecurityConfig": nsc_status,
        "counts": {
            "exported": len(exported),
            "implicitExported": len(implicit_exported),
            "deepLinks": len(deep_links),
            "providers": len(providers),
        },
    }


# ------------------------------------------------------------------- TLS

def classify_tls(class_records: list[dict], calls: list[dict]) -> dict:
    """TLS/pinning surface (pure).

    class_records = [{"class": dotted-name, "super": dotted-super-or-None}]
    calls         = dexmapper-shaped [{"class","method","targetClass",
                                       "targetMethod"}]
    Evidence: E1 for class presence, E2 for a captured call site."""
    trust_managers = [r["class"] for r in class_records
                      if r.get("super") == "javax.net.ssl.X509TrustManager"]
    pinner_refs = sorted({r["class"] for r in class_records
                          if "CertificatePinner" in r["class"]})
    okhttp = sorted({r["class"] for r in class_records
                     if r["class"].startswith("okhttp3.") or
                     r["class"].startswith("okio.")})[:10]
    js_bridge = sorted({f"{c.get('class')}.{c.get('method')}" for c in calls
                        if c.get("targetMethod") == "addJavascriptInterface"
                        and c.get("class")})
    return {
        "customTrustManagers": trust_managers,
        "certificatePinner": pinner_refs,
        "okhttpOkio": okhttp,
        "webViewJsBridgeCalls": js_bridge,
        "counts": {
            "customTrustManagers": len(trust_managers),
            "certificatePinner": len(pinner_refs),
            "okhttpOkio": len(okhttp),
            "webViewJsBridgeCalls": len(js_bridge),
        },
    }


# ------------------------------------------------------------- androguard glue

def _androguard_manifest(artifact: str) -> ET.Element:
    from .engines import _apkmod
    return _apkmod()._manifest_xml(artifact)


def _androguard_strings(artifact: str) -> list[tuple[str, str]]:
    """(value, source) for every DEX string + every manifest meta-data value."""
    from .engines import _apkmod
    apk = _apkmod()
    inv = apk.intake(artifact)
    out: list[tuple[str, str]] = []
    for n, d in apk._dex_objects(artifact):
        try:
            for s in d.get_strings():
                out.append((s, f"DEX:{n}"))
        except Exception:
            continue
    for k, v in (inv.get("metaData") or {}).items():
        if v:
            out.append((str(v), "manifest meta-data"))
    with zipfile.ZipFile(artifact) as z:
        for e in z.namelist():
            out.append((e, "zip-entry"))
    return out


def _androguard_class_records(artifact: str) -> list[dict]:
    from .engines import _apkmod
    apk = _apkmod()
    recs = []
    for _n, d in apk._dex_objects(artifact):
        for c in d.get_classes():
            sup = c.get_superclassname()
            recs.append({
                "class": c.get_name().strip("L;").replace("/", "."),
                "super": (sup or "").strip("L;").replace("/", "."),
            })
    return recs


def _androguard_calls(artifact: str, app_pkg: str) -> list[dict]:
    from . import dexmapper
    from .engines import _apkmod
    inv = _apkmod().intake(artifact)
    calls: list[dict] = []
    for n, b in dexmapper._dex_bytes(artifact):
        for call in dexmapper.map_dex(b, n, inv.get("package") or app_pkg).get("calls", []):
            calls.append(call)
    return calls


# ------------------------------------------------------------------ engine

def _scan_report(sec: dict, tls: dict, secrets: list[dict]) -> str:
    lines = ["# vibe /scan report card", ""]
    lines.append("Manifest security (E1/E2; runtime UNKNOWN until observed):")
    lines.append(f"  exported (explicit)      {sec['counts']['exported']}")
    for e in sec["exported"][:10]:
        lines.append(f"    - {e['kind']} {e['name']}  actions={e['actions'] or '-'}")
    lines.append(f"  exported (implicit)      {sec['counts']['implicitExported']} "
                 "(intent-filter, no android:exported — pre-31 semantics)")
    for e in sec["implicitExported"][:10]:
        lines.append(f"    - {e['kind']} {e['name']}  actions={e['actions'] or '-'}")
    fl = sec["flags"]
    lines.append(f"  debuggable={fl['debuggable'] or 'no'}  "
                 f"allowBackup={fl['allowBackup'] or 'no'}  "
                 f"usesCleartextTraffic={fl['usesCleartextTraffic'] or 'no'}  "
                 f"backupRules={fl['hasBackupRules'] or 'no'}")
    lines.append(f"  networkSecurityConfig    {sec['networkSecurityConfig']}")
    lines.append(f"  deep links               {sec['counts']['deepLinks']}")
    for d in sec["deepLinks"][:10]:
        lines.append(f"    - {d['kind']} {d['name']}  scheme={d['scheme']} "
                     f"host={d['host']} autoVerify={d['autoVerify']}")
    if sec["providers"]:
        lines.append(f"  providers                {len(sec['providers'])}")
        for p in sec["providers"][:10]:
            lines.append(f"    - {p['name']} exported={p['exported']} "
                         f"grantUri={p['grantUriPermissions']}")
    lines.append("")
    lines.append("TLS / pinning surface:")
    t = tls
    lines.append(f"  custom X509TrustManager subclasses  {t['counts']['customTrustManagers']}")
    for c in t["customTrustManagers"][:10]:
        lines.append(f"    - {c}")
    lines.append(f"  CertificatePinner refs              {t['counts']['certificatePinner']}")
    for c in t["certificatePinner"][:10]:
        lines.append(f"    - {c}")
    lines.append(f"  okhttp/okio classes (truncated)     {t['counts']['okhttpOkio']}")
    lines.append(f"  WebView addJavascriptInterface E2   {t['counts']['webViewJsBridgeCalls']}")
    for c in t["webViewJsBridgeCalls"][:10]:
        lines.append(f"    - {c}")
    lines.append("")
    lines.append(f"Secrets (MASKED — value[:4] + length; pattern {len([s for s in secrets if s['kind']=='pattern'])}, "
                 f"entropy {len([s for s in secrets if s['kind']=='entropy'])}):")
    for s in secrets[:ENTROPY_TOP_N + len([s for s in secrets if s['kind']=='pattern'])]:
        lines.append(f"  [{s['severity']}] {s['pattern']}  {s['value']}  "
                     f"H={s['entropy']}  src={s['source']}")
    if not secrets:
        lines.append("  none found (NOT OBSERVED — pattern list is reduced; "
                     "absence is not proof of secrecy)")
    lines.append("")
    lines.append("Static ceiling: manifest + DEX string/call census. "
                 "runtime: UNKNOWN until observed (E5).")
    return "\n".join(lines) + "\n"


class ScanSecEngine(core.Engine):
    """Engine: APK -> manifest security + secrets + TLS surface (job)."""

    spec = core.EngineSpec(
        name="scansec",
        description="security scan: manifest exported/intent-filters/deep-links/flags, "
                    "secrets (entropy + public formats, masked), TLS/pinning surface",
        formats=("apk", "apkx"),
    )

    def __init__(self, report_dir: str):
        self.report_dir = report_dir

    def can_run(self, artifact: str) -> bool:
        return artifact.lower().endswith((".apk", ".apkx"))

    def run(self, job: core.Job) -> core.EngineResult:
        from .engines import _apkmod
        if not _androguard_available():
            raise RuntimeError("androguard required for /scan "
                               "(uv pip install androguard)")
        apk = _apkmod()

        job.progress("intake", 10, "manifest + inventory")
        inv = apk.intake(job.artifact)
        with zipfile.ZipFile(job.artifact) as z:
            zip_names = z.namelist()
        root = _androguard_manifest(job.artifact)
        job.checkpoint("intake", {
            "package": inv.get("package"),
            "components": len(inv.get("activities") or []) +
                          len(inv.get("services") or []) +
                          len(inv.get("receivers") or []) +
                          len(inv.get("providers") or []),
        })

        job.progress("manifest", 30, "exported / intent-filters / deep links / flags")
        sec = scan_manifest(root, zip_names)
        job.checkpoint("manifest", sec["counts"])

        job.progress("secrets", 55, "string entropy + pattern census")
        strings = _androguard_strings(job.artifact)
        secrets = scan_strings(strings)
        job.checkpoint("secrets", {"count": len(secrets)})

        job.progress("tls", 75, "trust managers / pinners / JS bridge (androguard decoder)")
        class_records = _androguard_class_records(job.artifact)
        calls = _androguard_calls(job.artifact, inv.get("package") or "")
        tls = classify_tls(class_records, calls)
        job.checkpoint("tls", tls["counts"])

        job.progress("report", 95, "masked report card")
        report_md = _scan_report(sec, tls, secrets)
        os.makedirs(self.report_dir, exist_ok=True)
        rep_path = os.path.join(
            self.report_dir,
            f"scan-{(inv.get('sha256') or 'x')[:12]}-report.md")
        open(rep_path, "w", encoding="utf-8").write(report_md)
        job.progress("report", 100, "done")

        findings: list[dict] = []
        for i, e in enumerate(sec["exported"][:20]):
            findings.append(_mk_finding(f"EXPORTED-{i:02d}", "SECURITY", e,
                                        f"exported {e['kind']} {e['name']} "
                                        f"(explicit)", "manifest"))
        for i, e in enumerate(sec["implicitExported"][:20]):
            findings.append(_mk_finding(f"IMPEXP-{i:02d}", "SECURITY", e,
                                        f"implicitly exported {e['kind']} {e['name']} "
                                        f"(intent-filter, no android:exported)",
                                        "manifest"))
        for i, s in enumerate(secrets[:40]):
            findings.append(_mk_finding(
                f"SECRET-{i:03d}", "SECRET", s,
                f"secret-shaped string: {s['pattern']} ({s['value']})",
                s["source"], level="E1"))
        for i, c in enumerate(tls["customTrustManagers"][:20]):
            findings.append(_mk_finding(f"TLS-TM-{i:02d}", "TLS",
                                        {"class": c},
                                        f"custom X509TrustManager subclass {c} "
                                        f"(pinning or pinning-bypass machinery)",
                                        "DEX", level="E1"))
        for i, c in enumerate(tls["webViewJsBridgeCalls"][:20]):
            findings.append(_mk_finding(f"TLS-JSB-{i:02d}", "TLS", {"class": c},
                                        f"WebView.addJavascriptInterface call site "
                                        f"{c} (JS<->native bridge)", "DEX", level="E2"))
        if nsc_missing := (sec["networkSecurityConfig"].startswith("REFERENCED")):
            findings.append(_mk_finding("MANIFEST-NSC-01", "SECURITY",
                                        {"detail": sec["networkSecurityConfig"]},
                                        "networkSecurityConfig referenced but file "
                                        "not found in the APK", "manifest"))
        for f in findings:
            f["evidenceLevel"] = f.get("evidenceLevel", "E1")
            f["runtime"] = "UNKNOWN"
            f["falsification"] = f.get("falsification") or \
                ["presence-only: may be dead code or runtime-gated (Runtime: UNKNOWN)"]

        structural = {
            "security": sec,
            "tls": tls,
            "secrets": secrets,
        }
        return core.EngineResult(
            intake={k: inv.get(k) for k in
                    ("sha256", "size", "package", "versionName", "versionCode",
                     "minSdk", "targetSdk", "signingDigest")},
            structural=structural,
            findings=[core.normalize_finding(f, self.spec.name, i + 1)
                      for i, f in enumerate(findings)],
            report_md=report_md,
            outputs={"report": rep_path},
        )


def _mk_finding(fid: str, classification: str, loc: dict, detail: str,
                artifact: str, level: str = "E1") -> dict:
    return {
        "id": fid, "sdk": classification, "classification": classification,
        "title": detail,
        "evidence": [{"level": level, "artifact": artifact,
                      "class": loc.get("class"), "method": loc.get("method"),
                      "detail": detail}],
        "appCallers": [],
        **{k: v for k, v in loc.items() if k not in ("class", "method")},
    }


def _androguard_available() -> bool:
    try:
        import logging
        for name in ("androguard", "androguard.core", "loguru"):
            logging.getLogger(name).setLevel(logging.ERROR)
        try:
            from loguru import logger as _log
            _log.remove()
        except Exception:
            pass
        import warnings
        warnings.filterwarnings("ignore")
        from androguard.core.axml import AXMLPrinter  # noqa: F401
        return True
    except ImportError:
        return False
