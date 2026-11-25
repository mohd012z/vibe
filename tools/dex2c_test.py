"""v0.38 dex2c provider tests — pure checks, NO dex2cpp toolchain required.

Covers the stdlib half of tools/vibebot/dex2c.py (E1/E2/E3 detection
heuristics, driver output parsers, toolchain seam) and the gateway wiring
(/dex2c help + detect on a real APK, job ops via a FAKE driver script so CI
passes with no NDK/driver installed — the injectable-runner contract). The
real driver (convert -> protected APK) is exercised by the durable-host
smoke, not CI.
"""
import os
import sys
import tempfile
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.path.join(ROOT, "tools")
if TOOLS not in sys.path:
    sys.path.insert(0, TOOLS)

from vibebot import dex2c  # noqa: E402
from vibebot import gateway  # noqa: E402
from vibebot import core  # noqa: E402


# ---------------------------------------------------------------------------
# pure: detection heuristics
# ---------------------------------------------------------------------------


def test_so_family_hits():
    entries = ["lib/arm64-v8a/libnc.so", "lib/armeabi-v7a/libdex2cpp.so",
               "lib/arm64-v8a/libapp.so", "assets/libnc.so",
               "lib/arm64-v8a/libdex2c_extra.so", "res/x.png"]
    hits = dex2c.so_family_hits(entries)
    assert "lib/arm64-v8a/libnc.so" in hits
    assert "lib/armeabi-v7a/libdex2cpp.so" in hits
    assert "lib/arm64-v8a/libdex2c_extra.so" in hits
    assert "lib/arm64-v8a/libapp.so" not in hits
    assert "assets/libnc.so" not in hits  # not under lib/


def test_machinery_strings():
    data = (b"\x00pthread_rwlock_rdlock@LIBC\x00pthread_rwlock_wrlock@LIBC\x00"
            b"JNI_OnLoad\x00memset@LIBC\x00")
    f = dex2c.strings_suggest_machinery(data)
    assert f == ["pthread_rwlock_rdlock", "pthread_rwlock_wrlock"]
    # one identifier alone = coincidence, NOT machinery
    assert dex2c.strings_suggest_machinery(b"only pthread_rwlock_rdlock") == []


def test_long_jni_names():
    long1 = "Java_com_very_long_company_product_module_ClassName_" + "x" * 150
    assert dex2c.long_jni_names([long1, "Java_a_b_c"]) == [long1]
    # non-JNI-shaped long strings are not JNI names
    assert dex2c.long_jni_names(["s" * 300]) == []


def test_classify_protected():
    r = dex2c.classify(["lib/arm64-v8a/libnc.so"],
                       {"lib/arm64-v8a/libnc.so": b"pthread_rwlock_rdlock pthread_rwlock_wrlock"})
    assert r["protected"] is True
    levels = [e["level"] for e in r["evidence"]]
    assert "E1" in levels and "E2" in levels
    assert "PROTECTED" in r["verdict"]


def test_classify_not_protected():
    r = dex2c.classify(["lib/arm64-v8a/libapp.so"],
                       {"lib/arm64-v8a/libapp.so": b"plain native lib"})
    assert r["protected"] is False
    assert "NOT dex2c" in r["verdict"]


def test_classify_suspect_long_names_only():
    r = dex2c.classify([], {}, ["Java_" + "a_" * 80 + "_method__V"])
    assert r["protected"] is False
    assert "SUSPECT" in r["verdict"]


def test_zip_detect_real_apk():
    with tempfile.TemporaryDirectory() as td:
        apk = os.path.join(td, "plain.apk")
        so = (b"\x7fELF" + b"pthread_rwlock_rdlock pthread_rwlock_wrlock" * 8)
        with zipfile.ZipFile(apk, "w") as z:
            z.writestr("classes.dex", b"035\x00" + b"x" * 100)
            z.writestr("lib/arm64-v8a/libnc.so", so)
        res = dex2c.zip_detect(apk)
        assert res["protected"] is True
        assert res["e3"].startswith("NOT OBSERVED")


def test_zip_detect_negative():
    with tempfile.TemporaryDirectory() as td:
        apk = os.path.join(td, "plain.apk")
        with zipfile.ZipFile(apk, "w") as z:
            z.writestr("classes.dex", b"035\x00" + b"x" * 100)
            z.writestr("lib/arm64-v8a/libapp.so", b"plain")
        res = dex2c.zip_detect(apk)
        assert res["protected"] is False


# ---------------------------------------------------------------------------
# pure: driver output parsers
# ---------------------------------------------------------------------------


def test_parse_select_report():
    out = "Lcom/a/B;m()V\nLcom/a/C;n(Ljava/lang/String;)V\n# 2 selected, 5 skipped\n"
    rep = dex2c.parse_select_report(out)
    assert rep["count"] == 2 and rep["skipped"] == 5
    assert rep["selected"][0] == "Lcom/a/B;m()V"


def test_parse_convert_report():
    log = ("INFO selected 23 methods (559 skipped: -)\n"
           "INFO codegen: 23 ok, 0 errors\n"
           "INFO smali: 23 methods marked native\n"
           "INFO arm64-v8a {'ok': True, 'out': 'a.so'}\n"
           "INFO armeabi-v7a {'ok': True, 'out': 'b.so'}\n"
           "INFO apksigner verify: Verified using v2 scheme\n"
           "INFO OUTPUT /tmp/o.apk (12345 bytes)\n")
    c = dex2c.parse_convert_report(log)
    assert c["selected"] == 23 and c["skipped"] == 559
    assert c["codegenOk"] == 23 and c["codegenErrors"] == 0
    assert c["patched"] == 23
    assert c["abis"] == {"arm64-v8a": True, "armeabi-v7a": True}
    assert c["signed"] is True
    assert c["outSize"] == 12345 and c["output"].endswith("o.apk")


# ---------------------------------------------------------------------------
# toolchain seam
# ---------------------------------------------------------------------------


def test_toolchain_missing_honest():
    tc = dex2c.Toolchain({"VIBE_DEX2CPP_DRIVER": "/no/driver.py",
                          "VIBE_DEX2CPP_PYTHON": "/no/python"})
    assert not tc.available()
    assert "driver" in tc.missing() and "python" in tc.missing()
    try:
        tc.require()
        assert False, "should raise"
    except dex2c.Dex2cError as e:
        assert "NOT OBSERVED" in str(e)


# ---------------------------------------------------------------------------
# fake driver — the injectable-runner contract (CI without NDK)
# ---------------------------------------------------------------------------

FAKE_DRIVER = """\
import os, sys
cmd = sys.argv[1]
args = sys.argv[2:]
def arg(flag, default=None):
    return args[args.index(flag) + 1] if flag in args else default
if cmd == "select":
    print("Lcom/fake/A;m()V")
    print("Lcom/fake/B;n()V")
    sys.stderr.write("# 2 selected, 3 skipped\\n")
elif cmd == "codegen":
    out = arg("-o")
    os.makedirs(out, exist_ok=True)
    open(os.path.join(out, "Java_com_fake_A_m__V.cpp"), "w").write("// c")
    open(os.path.join(out, "Java_com_fake_B_n__V.cpp"), "w").write("// c")
    print("codegen 2 methods -> " + out)
elif cmd == "convert":
    out = arg("-o")
    open(out, "wb").write(b"FAKEPROTECTEDAPK" + b"0" * 64)
    sys.stderr.write(
        "INFO selected 2 methods (3 skipped: -)\\n"
        "INFO codegen: 2 ok, 0 errors\\n"
        "INFO smali: 2 methods marked native\\n"
        "INFO arm64-v8a {'ok': True}\\n"
        "INFO apksigner verify: Verified\\n"
        "INFO OUTPUT %s (76 bytes)\\n" % out)
else:
    sys.stderr.write("unknown cmd " + cmd + "\\n"); sys.exit(3)
"""


def _fake_env(td):
    drv = os.path.join(td, "fake_driver.py")
    open(drv, "w").write(FAKE_DRIVER)
    return {"VIBE_DEX2CPP_DRIVER": drv, "VIBE_DEX2CPP_PYTHON": sys.executable,
            "VIBE_DEX2CPP_KEYSTORE": ""}


def _fixture_apk(td):
    apk = os.path.join(td, "t.apk")
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("classes.dex", b"035\x00" + b"x" * 50)
    return apk


def test_convert_job_fake_driver():
    with tempfile.TemporaryDirectory() as td:
        rules = os.path.join(td, "rules.txt")
        open(rules, "w").write("Lcom/fake/A;.*\n")
        apk = _fixture_apk(td)
        gw = gateway.Gateway(td)
        r, job = gw.handle(f"/dex2c convert {apk} --rules {rules}",
                           user="test")
        assert job is not None and "ACK" in r, r
        # patch the engine's toolchain with the fake (injectable runner)
        gw.engines["dex2c"].tc = dex2c.Toolchain(_fake_env(td))
        done = gw.process_pending()
        j = [x for x in done if x is job][0]
        assert j.state == core.Job.COMPLETED, j.error
        res = j.result
        assert res is not None
        out = res.outputs["apk"]
        assert os.path.exists(out)
        assert res.structural["selected"] == 2
        assert res.structural["signed"] is True
        assert len(res.findings) == 1
        assert res.findings[0]["classification"] == "NATIVE_PROTECTION"


def test_codegen_job_fake_driver():
    with tempfile.TemporaryDirectory() as td:
        rules = os.path.join(td, "rules.txt")
        open(rules, "w").write("Lcom/fake/A;.*\n")
        apk = _fixture_apk(td)
        gw = gateway.Gateway(td)
        r, job = gw.handle(f"/dex2c codegen {apk} --rules {rules}", user="test")
        assert job is not None
        gw.engines["dex2c"].tc = dex2c.Toolchain(_fake_env(td))
        done = gw.process_pending()
        j = [x for x in done if x is job][0]
        assert j.state == core.Job.COMPLETED, j.error
        assert j.result is not None
        assert j.result.structural["cppFiles"] == 2


def test_select_job_fake_driver():
    with tempfile.TemporaryDirectory() as td:
        rules = os.path.join(td, "rules.txt")
        open(rules, "w").write("Lcom/fake/A;.*\n")
        apk = _fixture_apk(td)
        gw = gateway.Gateway(td)
        r, job = gw.handle(f"/dex2c select {apk} --rules {rules}", user="test")
        assert job is not None
        gw.engines["dex2c"].tc = dex2c.Toolchain(_fake_env(td))
        done = gw.process_pending()
        j = [x for x in done if x is job][0]
        assert j.state == core.Job.COMPLETED, j.error
        assert j.result is not None
        assert j.result.structural["selected"] == 2
        assert os.path.exists(j.result.outputs["report"])


def test_convert_degrades_without_toolchain():
    with tempfile.TemporaryDirectory() as td:
        rules = os.path.join(td, "rules.txt")
        open(rules, "w").write("Lcom/fake/A;.*\n")
        apk = _fixture_apk(td)
        env = {"VIBE_DEX2CPP_DRIVER": "/no/driver.py",
               "VIBE_DEX2CPP_PYTHON": "/no/python"}
        gw = gateway.Gateway(td)
        gw.engines["dex2c"].tc = dex2c.Toolchain(env)
        r, job = gw.handle(f"/dex2c convert {apk} --rules {rules}", user="test")
        assert job is not None and "ACK" in r
        done = gw.process_pending()
        j = [x for x in done if x is job][0]
        assert j.state == core.Job.FAILED
        assert "NOT OBSERVED" in (j.error or "")


def test_convert_missing_rules_honest():
    with tempfile.TemporaryDirectory() as td:
        apk = _fixture_apk(td)
        gw = gateway.Gateway(td)
        gw.engines["dex2c"].tc = dex2c.Toolchain(_fake_env(td))
        r, job = gw.handle(f"/dex2c convert {apk} --rules /no/rules.txt",
                           user="test")
        assert job is not None
        done = gw.process_pending()
        j = [x for x in done if x is job][0]
        assert j.state == core.Job.FAILED
        assert "rules" in (j.error or "").lower()


# ---------------------------------------------------------------------------
# gateway wiring
# ---------------------------------------------------------------------------


def test_dex2c_help_and_usage():
    with tempfile.TemporaryDirectory() as td:
        gw = gateway.Gateway(td)
        r, j = gw.handle("/dex2c help")
        assert j is None and "detect" in r and "convert" in r
        r, j = gw.handle("/dex2c")
        assert "detect" in r
        r, j = gw.handle("/dex2c bogus x")
        assert "unknown dex2c op" in r


def test_dex2c_detect_on_real_apk():
    fixture = os.path.join(ROOT, "tests", "fixtures", "fixture-demo.apk")
    if not os.path.exists(fixture):
        return  # fixture present on the durable host
    with tempfile.TemporaryDirectory() as td:
        gw = gateway.Gateway(td)
        r, j = gw.handle(f"/dex2c detect {fixture}")
        assert j is None, "detect is synchronous"
        assert "NOT dex2c" in r, r


def test_dex2c_detect_protected_apk():
    with tempfile.TemporaryDirectory() as td:
        apk = os.path.join(td, "prot.apk")
        so = b"pthread_rwlock_rdlock pthread_rwlock_wrlock"
        with zipfile.ZipFile(apk, "w") as z:
            z.writestr("classes.dex", b"035\x00" + b"x" * 50)
            z.writestr("lib/arm64-v8a/libdex2c.so", so)
        gw = gateway.Gateway(td)
        r, j = gw.handle(f"/dex2c detect {apk}")
        assert j is None
        assert "PROTECTED" in r, r
        assert "E1" in r and "E2" in r


def test_dex2c_detect_missing_file():
    with tempfile.TemporaryDirectory() as td:
        gw = gateway.Gateway(td)
        r, j = gw.handle(f"/dex2c detect {os.path.join(td, 'nope.apk')}")
        assert j is None and "not found" in r.lower() or "nope" in r


def test_dex2c_engine_registered_by_default():
    with tempfile.TemporaryDirectory() as td:
        gw = gateway.Gateway(td)
        assert "dex2c" in gw.engines, "Dex2cEngine must be a default engine"


def test_dex2c_in_registry_and_deploy_menu():
    from vibebot import registry
    import vibebot_deploy
    d2c = registry.get("dex2c")
    assert d2c is not None
    assert d2c["tier"] == 1
    names = [c[0] for c in vibebot_deploy.COMMANDS]
    assert "dex2c" in names
