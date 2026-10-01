#!/usr/bin/env python3
"""apkmod smoke test — runs the APK mod menu against the committed fixture APK
(tests/fixtures/fixture-demo.apk, self-built: 2 ad-SDK-like classes, 1 analytics
class, manifest meta-data for AdMob+AppLovin). Proves the module:
intake identity, E1/E2/E3 evidence, call graph chokepoints, authorization gate,
exit codes. CI installs androguard first (uv pip install androguard)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APK = os.path.join(ROOT, "tests", "fixtures", "fixture-demo.apk")
PY = sys.executable
EXTRA_FP = os.path.join(ROOT, "apk", "fingerprints.example-extra.json")

if not os.path.exists(APK):
    sys.exit(f"fixture missing: {APK}")


def run(*args: str) -> tuple[int, str, str]:
    p = subprocess.run([PY, *args], capture_output=True, text=True, cwd=ROOT)
    return p.returncode, p.stdout, p.stderr


failures = []


def check(name: str, cond: bool, detail: str = ""):
    print(f"  {'OK ' if cond else 'FAIL'} {name}" + (f"  ({detail})" if detail and not cond else ""))
    if not cond:
        failures.append(name)


# 1. intake
rc, out, err = run("tools/apkmod.py", APK, "--intake")
data = json.loads(out)
check("intake exit 0", rc == 0)
check("intake package", data.get("package") == "com.fixture.demo", out[:200])
check("intake sha256 present", len(data.get("sha256", "")) == 64)
check("intake dex found", "classes.dex" in data.get("dexFiles", []))

# 2. detect (with extra fingerprints for the fixture SDK)
rc, out, err = run("tools/apkmod.py", APK, "--detect", "--fingerprints", EXTRA_FP)
check("detect exit 0", rc == 0, err[-200:])
check("detect ADMOB E2", "ADMOB" in out and "E2" in out)
check("detect APPLOVIN E2", "APPLOVIN" in out)
check("detect E3 app callers", "callers=1" in out or "callers=2" in out)
check("detect runtime UNKNOWN", "runtime=UNKNOWN" in out)

# 3. graph shows chokepoints
rc, out, err = run("tools/apkmod.py", APK, "--graph", "--fingerprints", EXTRA_FP)
check("graph exit 0", rc == 0)
check("graph chokepoint DemoApp.onCreate", "DemoApp.onCreate()" in out, out[-400:])
check("graph invokes InterstitialAd.load", "InterstitialAd.load()" in out)

# 4. authorization gate
rc, out, err = run("tools/apkmod.py", APK, "--detect", "--plan")
check("plan without --authorized exits 3", rc == 3, f"rc={rc}")
check("plan refusal message", "--authorized" in err or "--authorized" in out)

with tempfile.TemporaryDirectory() as td:
    rc, out, err = run("tools/apkmod.py", APK, "--plan",
                       "--fingerprints", EXTRA_FP,
                       "--authorized", "test: self-built fixture, rights held",
                       "--out-dir", td)
    check("plan with --authorized exit 0", rc == 0, err[-200:])
    plan = json.load(open(os.path.join(td, "patch-plan.json")))
    check("plan scope dry-run", "DRY-RUN" in plan["scope"])
    check("plan records authorization", "rights held" in plan["authorization"]["statement"])
    check("plan candidates >= 5", len(plan["candidates"]) >= 5, str(len(plan["candidates"])))
    c0 = plan["candidates"][0]
    check("plan candidate has chokepoint", "()" in c0["chokepoint"])
    check("plan candidate has rollback", "rollback" in c0 and c0["rollback"])
    check("plan candidate default STUB-NOOP", "STUB-NOOP" in c0["action"])

# 5. report
with tempfile.TemporaryDirectory() as td:
    rc, out, err = run("tools/apkmod.py", APK, "--detect",
                       "--fingerprints", EXTRA_FP, "--report", "--out-dir", td)
    check("report exit 0", rc == 0)
    rep = [l for l in out.splitlines() if l.startswith("report:")]
    check("report path printed", bool(rep))
    txt = open(rep[0].split()[-1]).read() if rep else ""
    check("report has findings table", "| FND-" in txt)
    check("report static ceiling note", "presence ≠ execution" in txt or "E3" in txt)

# 6. bad path exit code
rc, out, err = run("tools/apkmod.py", "/nope/missing.apk", "--intake")
check("bad path exits 3", rc == 3, f"rc={rc}")

print()
if failures:
    print(f"apkmod smoke: FAILED ({len(failures)}): {failures}")
    sys.exit(1)
print("apkmod smoke: ALL PASS")
