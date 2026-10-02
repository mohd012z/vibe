import zipfile

import pytest

from tools.vibe_artifact_router import ApkArtifactRouter, Domain, TargetResolver, validate_radare_target
from tools.vibe_apk_adapters import Radare2ReadProvider


class FakeRunner:
    def __init__(self, outputs=None): self.outputs = outputs or {}
    def run(self, argv): return self.outputs.get(tuple(argv), "[]")


def make_apk(tmp_path):
    apk = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("AndroidManifest.xml", b"manifest")
        z.writestr("resources.arsc", b"resources")
        z.writestr("res/layout/main.xml", b"layout")
        z.writestr("classes.dex", b"dex")
        z.writestr("classes2.dex", b"dex2")
        z.writestr("lib/arm64-v8a/libdemo.so", b"\x7fELF")
    return apk


def test_apk_router_maps_domains_and_abi(tmp_path):
    mapped = ApkArtifactRouter().inspect(make_apk(tmp_path))
    assert {Domain.MANIFEST, Domain.RESOURCE, Domain.DEX, Domain.NATIVE, Domain.CONTAINER} <= mapped.domains()
    assert mapped.native_parts()[0].abi == "arm64-v8a"


def test_provider_order_is_domain_aware():
    router = ApkArtifactRouter()
    assert router.provider_order("REFERENCE_IN", Domain.NATIVE)[:2] == ("radare2", "ghidra")
    assert router.provider_order("STRING_SEARCH", Domain.DEX)[0] == "jadx"
    assert router.provider_order("ARTIFACT_INDEX", Domain.MANIFEST)[0] == "apktool"

@pytest.mark.parametrize("target,domain", [
    ("0x401000", Domain.NATIVE),
    ("Java_com_demo_Main_verify", Domain.NATIVE),
    ("Lcom/demo/Main;->verify", Domain.SMALI),
    ("com.demo.Main.verify", Domain.DEX),
])
def test_target_resolver_classifies_known_shapes(target, domain):
    assert TargetResolver().resolve(target).domain is domain


def test_ambiguous_target_stays_unknown():
    hint = TargetResolver().resolve("verify")
    assert hint.domain is Domain.UNKNOWN
    assert hint.confidence == 0.0


def test_radare_target_validator_rejects_command_language():
    assert validate_radare_target("0x401000") == "0x401000"
    assert validate_radare_target("sym.Java_com_demo_Main_verify") == "sym.Java_com_demo_Main_verify"
    for bad in ("0x10;wx 90", "0x10 @ 0x20", "$(cmd)", "sym.x\nq"):
        with pytest.raises(ValueError):
            validate_radare_target(bad)


def test_radare_provider_rejects_unsafe_target_before_runner(tmp_path):
    provider = Radare2ReadProvider(tmp_path / "lib.so", FakeRunner())
    with pytest.raises(ValueError, match="unsafe"):
        provider.observe("REFERENCE_IN", "0x10;wx 90")
