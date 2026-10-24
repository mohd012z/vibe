#!/usr/bin/env python3
"""scansec unit tests — pure functions, no androguard.

Covers the three scan surfaces with synthetic inputs (manifest XML strings,
string lists, class/call records) + the report renderer + the engine's
finding builder. Run:  python tools/scansec_test.py
Exit 0 = all pass.
"""

import os
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vibebot import scansec  # noqa: E402

FAILS = 0


def check(name, cond, detail=""):
    global FAILS
    print(f"  {'OK  ' if cond else 'FAIL'} {name}" + (f"   ({detail})" if detail and not cond else ""))
    if not cond:
        FAILS += 1


# ------------------------------------------------------------------ entropy
print("== shannon_entropy (pure) ==")
check("empty -> 0.0", scansec.shannon_entropy("") == 0.0)
check("single repeated char -> 0.0", scansec.shannon_entropy("aaaaaaaa") == 0.0)
check("two-equal-symbols -> 1.0", abs(scansec.shannon_entropy("abababab") - 1.0) < 1e-9)
e = scansec.shannon_entropy("Q7xK9mB2wL5pR8tY")
check("mixed alnum >= 3.5", e >= 3.5, f"H={e:.3f}")
low = scansec.shannon_entropy("the quick brown fox")
check("english text < high-entropy mixed", low < e, f"low={low:.3f} high={e:.3f}")

# ------------------------------------------------------------------- mask
print("== mask (secrets must not echo whole values) ==")
long_secret = "AKIAABCDEFGHIJKLMNOP"
m = scansec.mask(long_secret)
check("mask hides the tail", "MNOP" not in m and m.startswith("AKIA"), m)
check("mask records length", f"(len {len(long_secret)})" in m, m)
short = scansec.mask("ab12")
check("short mask keeps only 2 chars", short.startswith("ab") and "12" not in short, short)

# ------------------------------------------------------- pattern detection
print("== find_secret_patterns (public formats) ==")
out = []
scansec.find_secret_patterns("aws: AKIAIOSFODNN7EXAMPLE end", "dex", out)
check("AWS key hit", any(f["pattern"] == "AWS access key ID" for f in out), str(out))
check("AWS severity HIGH", out and out[0]["severity"] == "HIGH")
check("AWS value masked", out and "OSFODNN7EXAMPLE" not in out[0]["value"], str(out[:1]))

out = []
ghp = "ghp_" + "a1B2" * 9  # 36 chars after the prefix
scansec.find_secret_patterns("token " + ghp + " end", "zip-entry", out)
check("github classic token hit", any(f["pattern"] == "GitHub token (classic/pat)" for f in out),
      str(out))
out = []
gkey = "AIza" + "SyA123456789012345678901234567890abcd"[:35]
assert len(gkey) == 39
scansec.find_secret_patterns("key " + gkey + " end", "meta", out)
check("google API key hit", any(f["pattern"] == "Google API key" for f in out), str(out))
check("google severity MED", out and out[0]["severity"] == "MED")

out = []
scansec.find_secret_patterns("-----BEGIN RSA PRIVATE KEY-----", "asset", out)
check("private key block hit", any("Private key block" in f["pattern"] for f in out), str(out))

out = []
scansec.find_secret_patterns("xoxb-12345-67890-abcdef", "string", out)
check("slack token hit", any(f["pattern"] == "Slack token" for f in out), str(out))

out = []
scansec.find_secret_patterns("com.example.MainActivity onCreate", "dex", out)
check("benign string: no hit", out == [], str(out))

# cap: one huge string with many matches must not explode the report
out = []
big = " ".join(["AKIA" + "A" * 16] * 100)
scansec.find_secret_patterns(big, "dex", out, cap=5)
check("cap honored", len(out) <= 5, str(len(out)))

# ----------------------------------------------------------- entropy census
print("== entropy_census (structural DEX strings excluded) ==")
census = scansec.entropy_census(
    ["Lcom/example/foo/Bar;", "(Ljava/lang/String;I)V",          # structural -> excluded
     "Q7xK9mB2wL5pR8tYzV3nG6hJ",                                   # high entropy -> in
     "hello world this is short",                                  # low entropy -> out
     "aaaaaaaaaaaaaaaa"],                                          # 16 chars, H=0 -> out
    "dex")
vals = [c["value"] for c in census]
check("exactly 1 high-entropy survivor", len(census) == 1, str(census))
check("survivor is the mixed string", any(v.startswith("Q7xK") for v in vals), str(vals))
check("survivor masked", all("Q7xK9mB2" not in v for v in vals), str(vals))
check("survivor entropy >= threshold", census and census[0]["entropy"] >= scansec.ENTROPY_MIN,
      str(census))

# ------------------------------------------------------------ scan_manifest
print("== scan_manifest (pure over XML text) ==")
MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.demo.app" android:versionCode="1" android:versionName="1.0">
  <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="34"/>
  <uses-permission android:name="android.permission.INTERNET"/>
  <application android:allowBackup="true" android:usesCleartextTraffic="true"
      android:networkSecurityConfig="@xml/network_security_config" android:debuggable="false">
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
      </intent-filter>
    </activity>
    <activity android:name=".DeepLink">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <data android:scheme="demoapp" android:host="open"/>
      </intent-filter>
    </activity>
    <service android:name=".BgService" android:exported="false">
      <intent-filter>
        <action android:name="com.demo.BG"/>
      </intent-filter>
    </service>
    <receiver android:name=".BootRecv">
      <intent-filter>
        <action android:name="android.intent.action.BOOT_COMPLETED"/>
      </intent-filter>
    </receiver>
    <provider android:name=".FileProvider" android:exported="false"
        android:grantUriPermissions="true">
      <meta-data android:name="android.support.FILE_PROVIDER_PATHS"
          android:resource="@xml/provider_paths"/>
    </provider>
  </application>
</manifest>
"""


def _parse(s):
    return ET.fromstring(s)


sec = scansec.scan_manifest(_parse(MANIFEST), ["res/xml/network_security_config"])
check("flags: allowBackup true", sec["flags"]["allowBackup"] == "true", str(sec["flags"]))
check("flags: cleartext true", sec["flags"]["usesCleartextTraffic"] == "true")
check("flags: debuggable false", sec["flags"]["debuggable"] == "false")
check("nsc referenced + present", sec["networkSecurityConfig"] == "present in APK",
      sec["networkSecurityConfig"])
check("explicit exported = MainActivity only",
      [e["name"] for e in sec["exported"]] == [".MainActivity"], str(sec["exported"]))
check("implicit exported = DeepLink + BootRecv (no android:exported + intent-filter)",
      sorted(e["name"] for e in sec["implicitExported"]) == [".BootRecv", ".DeepLink"],
      str(sec["implicitExported"]))
check("explicit exported has basis explicit", sec["exported"][0]["basis"] == "explicit")
check("deep link captured", sec["counts"]["deepLinks"] == 1, str(sec["deepLinks"]))
check("deep link scheme/host", sec["deepLinks"][0]["scheme"] == "demoapp"
      and sec["deepLinks"][0]["host"] == "open")
check("provider recorded", sec["counts"]["providers"] == 1, str(sec["providers"]))
check("provider grantUriPermissions", sec["providers"][0]["grantUriPermissions"] == "true")

# nsc referenced but NOT shipped in the APK -> its own finding input
sec2 = scansec.scan_manifest(_parse(MANIFEST), ["res/xml/provider_paths"])
check("nsc missing detected", sec2["networkSecurityConfig"].startswith("REFERENCED BUT NOT FOUND"),
      sec2["networkSecurityConfig"])
# no nsc at all
MANI_NOSC = MANIFEST.replace(' android:networkSecurityConfig="@xml/network_security_config"', "")
sec3 = scansec.scan_manifest(_parse(MANI_NOSC), [])
check("nsc not referenced", sec3["networkSecurityConfig"] == "NOT REFERENCED")
# autoVerify deep link
MANI_AV = MANIFEST.replace('android:host="open"',
                           'android:host="open" android:autoVerify="true"')
sec4 = scansec.scan_manifest(_parse(MANI_AV), [])
check("autoVerify deep link flagged",
      any(d["autoVerify"] for d in sec4["deepLinks"]), str(sec4["deepLinks"]))
# explicit exported=false + intent-filter is NOT implicitly exported
check("BgService (exported=false) not implicit",
      all(e["name"] != ".BgService" for e in sec["implicitExported"]))

# -------------------------------------------------------------- classify_tls
print("== classify_tls (pure) ==")
recs = [
    {"class": "com.app.MyTrustManager", "super": "javax.net.ssl.X509TrustManager"},
    {"class": "com.app.Net", "super": "java.lang.Object"},
    {"class": "okhttp3.OkHttpClient", "super": "java.lang.Object"},
    {"class": "okio.Buffer", "super": "okio.Reflector"},
    {"class": "com.app.PinnerHelper", "super": "java.lang.Object"},
    {"class": "com.app.WebThing", "super": "java.lang.Object"},
]
calls = [
    {"class": "com.app.WebThing", "method": "init",
     "targetClass": "android.webkit.WebView",
     "targetMethod": "addJavascriptInterface"},
    {"class": "com.app.Net", "method": "go",
     "targetClass": "okhttp3.OkHttpClient", "targetMethod": "newBuilder"},
]
tls = scansec.classify_tls(recs, calls)
check("custom trust manager found",
      tls["customTrustManagers"] == ["com.app.MyTrustManager"], str(tls))
check("okhttp/okio found", "okhttp3.OkHttpClient" in tls["okhttpOkio"]
      and "okio.Buffer" in tls["okhttpOkio"], str(tls["okhttpOkio"]))
check("js bridge E2 call site", tls["webViewJsBridgeCalls"] == ["com.app.WebThing.init"],
      str(tls["webViewJsBridgeCalls"]))
check("counts consistent", tls["counts"]["customTrustManagers"] == 1
      and tls["counts"]["webViewJsBridgeCalls"] == 1, str(tls["counts"]))
tls0 = scansec.classify_tls([], [])
check("empty input -> empty", tls0["counts"] == {"customTrustManagers": 0,
                                                 "certificatePinner": 0,
                                                 "okhttpOkio": 0,
                                                 "webViewJsBridgeCalls": 0}, str(tls0))

# ------------------------------------------------------------------- report
print("== _scan_report (rendering) ==")
rep = scansec._scan_report(sec, tls,
                           [{"kind": "pattern", "pattern": "AWS access key ID",
                             "severity": "HIGH", "source": "DEX:classes.dex",
                             "value": "AKIA…(len 20)", "entropy": 3.7, "level": "E1"}])
check("report has manifest section", "Manifest security" in rep)
check("report lists exported", ".MainActivity" in rep)
check("report lists nsc state", "present in APK" in rep)
check("report lists TLS", "MyTrustManager" in rep)
check("report lists masked secret", "AKIA…(len 20)" in rep)
check("report keeps runtime honest", "runtime: UNKNOWN" in rep)
check("report has no FULL aws key", "AKIAABCDEFGHIJKLMNOP" not in rep)
rep0 = scansec._scan_report(sec3, tls0, [])
check("empty secrets -> honest NOT OBSERVED", "NOT OBSERVED" in rep0, rep0[-300:])

# ----------------------------------------------------------------- findings
print("== _mk_finding -> normalize_finding schema ==")
from vibebot import core  # noqa: E402
raw = scansec._mk_finding("EXPORTED-00", "SECURITY", {"name": ".MainActivity"},
                          "exported activity .MainActivity (explicit)", "manifest")
norm = core.normalize_finding(raw, "scansec", 1)
check("normalized id preserved", norm["id"] == "EXPORTED-00", str(norm["id"]))
check("normalized classification", norm["classification"] == "SECURITY")
check("normalized runtime UNKNOWN", norm["verification"]["runtime"] == "UNKNOWN")
check("normalized evidence level E1", norm["evidenceLevel"] == "E1")
check("normalized falsification present", norm["alternatives"])
e2 = core.normalize_finding(
    scansec._mk_finding("TLS-JSB-00", "TLS", {"class": "com.app.WebThing.init"},
                        "WebView bridge", "DEX", level="E2"), "scansec", 2)
check("E2 level propagates", e2["evidenceLevel"] == "E2", str(e2["evidenceLevel"]))

# ------------------------------------------------------------- end-to-end pure
print("== scan_strings dedup (same value twice) ==")
ss = scansec.scan_strings([("AKIAIOSFODNN7EXAMPLE", "dex:a"),
                           ("AKIAIOSFODNN7EXAMPLE", "dex:b")])
check("pattern hits once per source", sum(1 for f in ss if f["kind"] == "pattern") == 2,
      str(ss))

print()
if FAILS:
    print(f"scansec: {FAILS} FAIL")
    sys.exit(1)
print("scansec: ALL PASS")
