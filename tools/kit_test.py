"""v0.37 kit workbench tests — pure-function checks, NO Android toolchain.

Covers the stdlib half of tools/vibebot/kit.py (zip workbench, encrypt/
decrypt round-trip, smali regex battery, pattern DB) and the gateway wiring
(/kit help/presets + honest degrade for missing toolchain). The apktool
patch/compile path is exercised by the durable-host smoke, not CI.
"""
import os
import sys
import tempfile
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.path.join(ROOT, "tools")
if TOOLS not in sys.path:
    sys.path.insert(0, TOOLS)

from vibebot import kit  # noqa: E402
from vibebot import gateway  # noqa: E402
from vibebot import engines  # noqa: E402


def _mk_apk(path, entries):
    with zipfile.ZipFile(path, "w") as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return path


# App code: its OWN ad wrapper (showBanner) + a VIP gate (isVip()Z) + lifecycle.
# Name-based patterns reach the app's wrappers (the header names the method).
APP_SMALI = """.class public Lcom/app/Ads;
.method public showBanner()V
    .registers 2
    const/4 v0, 0x0
    invoke-static {v0}, Lcom/google/android/gms/ads/Banner;->load()V
    return-void
.end method

.method public isVip()Z
    .registers 2
    .locals 1
    const/4 v0, 0x0
    return v0
.end method

.method public onResume()V
    .registers 2
    .line 12
    invoke-super {p0}, Landroid/app/Activity;->onResume()V
    return-void
.end method
"""

# The ad SDK file: class-scope patterns match the .class directive and void
# every non-<init> method (the header can't see the owning class, so name
# patterns can't reach these — file-level is the real AdsRegex SDK move).
SDK_SMALI = """.class public Lcom/google/android/gms/ads/Banner;
.super Ljava/lang/Object;

.method constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public static load()V
    .registers 1
    invoke-static {}, Lcom/google/android/gms/ads/AdRequest;->build()V
    return-void
.end method

.method public show()V
    .registers 2
    invoke-virtual {p0}, Lcom/google/android/gms/ads/AdView;->measure()V
    return-void
.end method
"""


def test_zip_inventory_read_write_delete():
    with tempfile.TemporaryDirectory() as td:
        apk = _mk_apk(os.path.join(td, "a.apk"),
                      {"classes.dex": b"DEXTIME", "res/x.txt": b"hello"})
        inv = kit.zip_inventory(apk)
        assert len(inv) == 2
        data = kit.zip_read(apk, "res/x.txt")
        assert data == b"hello"
        out = os.path.join(td, "a.write.apk")
        kit.zip_write(apk, out, "res/x.txt", b"world")
        assert kit.zip_read(out, "res/x.txt") == b"world"
        out2 = os.path.join(td, "a.del.apk")
        kit.zip_delete(apk, out2, "res/x.txt")
        try:
            kit.zip_read(out2, "res/x.txt")
            assert False, "should be gone"
        except kit.KitError:
            pass


def test_zip_read_missing_entry_honest():
    with tempfile.TemporaryDirectory() as td:
        apk = _mk_apk(os.path.join(td, "a.apk"), {"classes.dex": b"D"})
        try:
            kit.zip_read(apk, "nope.txt")
            assert False
        except kit.KitError as e:
            assert "not found" in str(e)


def test_encrypt_decrypt_roundtrip():
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "a.apk")
        _mk_apk(src, {"classes.dex": b"PK\x03\x04" + b"x" * 100})
        enc = os.path.join(td, "a.enc")
        kit.encrypt_apk(src, enc, "secretpass")
        assert open(enc, "rb").read() != open(src, "rb").read()
        dec = os.path.join(td, "a.dec.apk")
        kit.decrypt_file(enc, dec, "secretpass")
        assert open(dec, "rb").read() == open(src, "rb").read()
        # wrong key -> honest error (PK magic check)
        try:
            kit.decrypt_file(enc, os.path.join(td, "b.dec"), "wrong")
            assert False, "wrong key should fail PK check"
        except kit.KitError:
            pass


def test_xor_keystream_no_repeat_byte():
    ks = kit._keystream("k", "n", 128)
    assert len(ks) == 128
    assert ks[:8] != ks[8:16], "keystream must not repeat a block"


def test_smali_regex_app_owned_ad_void():
    # name-based: void the app's OWN showBanner (the chokepoint). The header
    # names the method, so a name pattern reaches it.
    new, n = kit.apply_smali_regex(APP_SMALI, kit.PATCH_PRESETS["ads"][0]["pattern"],
                                   "", whole_method=True)
    assert n >= 1, "app showBanner should be voided by name pattern"
    # the body invoke to Banner;->load is gone; the method is intact
    assert "invoke-static {v0}, Lcom/google/android/gms/ads/Banner;->load" not in new
    assert ".method public showBanner()V" in new
    assert "return-void" in new


def test_count_param_regs_descriptor():
    # DEX descriptors have NO commas — reference types are 'Ltype;' and
    # wide types (J/D) take 2 registers. This exact counting is what keeps
    # .registers valid (a build failure if wrong).
    assert kit._count_param_regs("") == 0
    assert kit._count_param_regs("I") == 1
    assert kit._count_param_regs("JJ") == 4          # two longs
    assert kit._count_param_regs("J") == 2           # one long = 2 regs
    assert kit._count_param_regs("Ljava/lang/String;") == 1
    # the real case that broke the build: two reference params = 2 regs
    assert kit._count_param_regs(
        "Landroid/app/Activity;Ljava/lang/String;") == 2
    assert kit._count_param_regs("[I") == 1          # int[] = 1 reg
    assert kit._count_param_regs("ILjava/lang/Object;J") == 1 + 1 + 2


def test_void_multiref_params_registers_valid():
    # static showBanner(Activity,String)V: 2 reference params -> .registers 2
    # (this is the fixture case that failed smali assembly before the fix).
    head = ".method public static showBanner(Landroid/app/Activity;Ljava/lang/String;)V\n"
    txt = head + "    .locals 0\n    return-void\n.end method"
    m = next(iter(kit._smali_method_body(txt).finditer(txt)))
    v = kit._void_method(m)
    assert ".registers 2" in v, v
    assert ".locals" not in v


def test_smali_class_scope_voids_sdk():
    # class-scope: void every non-<init> method in the SDK file.
    new, n = kit._void_class_scope(SDK_SMALI)
    assert n == 2, f"expected load()+show() voided, got {n}"
    # the SDK bodies are gone
    assert "AdRequest;->build" not in new
    assert "AdView;->measure" not in new
    # <init> is preserved (constructors set up state)
    assert "invoke-direct {p0}, Ljava/lang/Object;-><init>()V" in new


def test_smali_void_bool_gate_is_vip_true():
    # vip-name voids isVip()Z. A ()Z method cannot "return-void" (dex
    # verification error => crash); the void must flip it to TRUE.
    new, n = kit.apply_smali_regex(APP_SMALI, kit.PATCH_PRESETS["vip"][1]["pattern"],
                                   "", whole_method=True)
    assert n == 1, f"expected isVip()Z voided, got {n}"
    # flip is TRUE, not void (a ()Z method cannot "return-void" — dex type
    # error => crash). Scope to the isVip block (onResume()V has its own
    # return-void, so the check can't be global).
    block = new[new.index(".method public isVip()Z"):new.index(".end method",
                                                               new.index("isVip"))]
    assert "return-void" not in block  # would be a dex type error for ()Z
    # flipped true; a no-arg instance method uses p0 (=this, always valid),
    # so .registers is just 1 and no .locals is needed.
    assert "const/4 p0, 0x1" in block
    assert "return p0" in block
    assert ".registers 1" in block
    assert ".locals" not in block


def test_smali_regex_bool_flip():
    pat = kit.PATCH_PRESETS["vip"][0]
    new, n = kit.apply_smali_regex(APP_SMALI, pat["pattern"],
                                   pat["replacement"], whole_method=False)
    assert n >= 1, "const/4 bool flip should match"
    assert "0x1" in new


def test_strip_debug_info():
    new, n = kit.strip_debug_info(APP_SMALI)
    assert ".line" not in new
    assert n >= 1
    # method structure preserved
    assert ".method public onResume()V" in new


def test_patch_smali_dir_hits_and_report():
    with tempfile.TemporaryDirectory() as td:
        sm = os.path.join(td, "smali")
        os.makedirs(os.path.join(sm, "com/app"))
        os.makedirs(os.path.join(sm, "com/google/android/gms/ads"))
        open(os.path.join(sm, "com/app/Ads.smali"), "w").write(APP_SMALI)
        open(os.path.join(sm, "com/google/android/gms/ads/Banner.smali"),
             "w").write(SDK_SMALI)
        patterns = kit.PATCH_PRESETS["ads"]
        rep = kit.patch_smali_dir(sm, patterns)
        assert rep, "expected at least one hit"
        # class-scope voided the SDK file (the real AdsRegex SDK move)
        assert any(r["pattern"] == "ads-sdk-gms" for r in rep)
        # the app's own showBanner was voided by name
        assert any(r["pattern"] == "ads-banner" for r in rep)
        # the SDK load() body is gone
        assert open(os.path.join(sm, "com/google/android/gms/ads/Banner.smali")
                    ).read().count("AdRequest;->build") == 0


def test_preset_db_shape():
    # every preset resolves to at least one pattern; every pattern has the
    # required keys.
    for preset, cats in kit.PRESET_CATS.items():
        pats = kit.preset_patterns(preset)
        assert pats, f"preset {preset} empty"
        for p in pats:
            assert "id" in p and "pattern" in p, p
    for cat, pats in kit.PATCH_PRESETS.items():
        for p in pats:
            assert "replacement" in p, (cat, p["id"])


def test_preset_unknown_honest():
    try:
        kit.preset_patterns("nope")
        assert False
    except kit.KitError as e:
        assert "unknown preset" in str(e)


def test_kit_help_and_presets_gateway():
    with tempfile.TemporaryDirectory() as td:
        gw = gateway.Gateway(td, {"mock": engines.MockEngine()})
        r, j = gw.handle("/kit help")
        assert "extract" in r and "patch" in r and j is None
        r2, _ = gw.handle("/kit presets")
        assert "vip" in r2 and "ads" in r2


def test_kit_engine_registered_by_default():
    with tempfile.TemporaryDirectory() as td:
        gw = gateway.Gateway(td)
        assert "kit" in gw.engines, "KitEngine must be a default engine"


def test_kit_extract_on_real_apk():
    with tempfile.TemporaryDirectory() as td:
        fixture = os.path.join(ROOT, "tests", "fixtures", "fixture-demo.apk")
        if not os.path.exists(fixture):
            return  # fixture present on the durable host
        gw = gateway.Gateway(td, {"mock": engines.MockEngine()})
        r, j = gw.handle(f"/kit extract {fixture}")
        assert j is None
        assert "entries" in r and "classes.dex" in r


def test_kit_read_and_delete():
    with tempfile.TemporaryDirectory() as td:
        fixture = os.path.join(ROOT, "tests", "fixtures", "fixture-demo.apk")
        if not os.path.exists(fixture):
            return
        gw = gateway.Gateway(td, {"mock": engines.MockEngine()})
        r, _ = gw.handle(f"/kit read {fixture} AndroidManifest.xml")
        assert "bytes" in r
        r2, _ = gw.handle(f"/kit delete {fixture} META-INF/MANIFEST.MF")
        assert "delete" in r2.lower()


def test_kit_patch_degrades_without_toolchain():
    # point the toolchain at nonexistent paths -> /kit patch must ACK a job
    # that FAILS with an honest KitError, not crash the gateway.
    with tempfile.TemporaryDirectory() as td:
        env = {"VIBE_KIT_JAVA": "/no/java", "VIBE_KIT_APKTOOL": "/no/apktool.jar",
               "VIBE_KIT_BUILD_TOOLS": "/no/bt"}
        gw = gateway.Gateway(td, {"kit": engines.KitEngine(
            os.path.join(td, "kit-out"), toolchain=kit.Toolchain(env)),
            "mock": engines.MockEngine()})
        fixture = os.path.join(ROOT, "tests", "fixtures", "fixture-demo.apk")
        r, job = gw.handle(f"/kit patch {fixture} --preset vip")
        assert job is not None, r
        assert "ACK" in r
        done = gw.process_pending()
        assert done and done[0].state == gateway.core.Job.FAILED
        assert "NOT OBSERVED" in (done[0].error or "")
