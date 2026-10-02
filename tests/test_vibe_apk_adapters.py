import json
from pathlib import Path

from tools.vibe_apk_adapters import ApktoolReadProvider, JadxReadProvider, Radare2ReadProvider, ToolUnavailable


class FakeRunner:
    def __init__(self, outputs=None): self.outputs = outputs or {}
    def run(self, argv): return self.outputs.get(tuple(argv), "[]")


def test_radare_string_json_becomes_normalized_observations(tmp_path):
    binary = str(tmp_path / "libx.so")
    argv = ("r2", "-2", "-q", "-c", "izzj", binary)
    runner = FakeRunner({argv: json.dumps([{"vaddr": 4096, "string": "hello"}])})
    rows = Radare2ReadProvider(binary, runner).observe("STRING_SEARCH", None)
    assert rows[0].kind == "string"
    assert rows[0].value == {"offset": 4096, "text": "hello"}


def test_radare_xref_uses_resolved_target_without_shell(tmp_path):
    binary = str(tmp_path / "libx.so")
    argv = ("r2", "-2", "-q", "-c", "axtj @ 0x1000", binary)
    runner = FakeRunner({argv: json.dumps([{"from": 8192, "to": 4096}])})
    rows = Radare2ReadProvider(binary, runner).observe("REFERENCE_IN", "0x1000")
    assert rows[0].kind == "xref_in"
    assert rows[0].value["from"] == 8192


def test_jadx_indexes_existing_workspace_without_running_tool(tmp_path):
    root = tmp_path / "work" / "jadx" / "sources" / "a"
    root.mkdir(parents=True)
    (root / "Main.java").write_text("class Main {}", encoding="utf-8")
    provider = JadxReadProvider(tmp_path / "app.apk", tmp_path / "work", FakeRunner())
    rows = provider.observe("ARTIFACT_INDEX", None)
    assert any(r.value.endswith("Main.java") for r in rows)


def test_jadx_string_search_is_bounded_and_reports_location(tmp_path):
    root = tmp_path / "work" / "jadx" / "sources"
    root.mkdir(parents=True)
    (root / "Main.java").write_text('String x = "needle";\n', encoding="utf-8")
    provider = JadxReadProvider(tmp_path / "app.apk", tmp_path / "work", FakeRunner())
    rows = provider.observe("STRING_SEARCH", "needle")
    assert rows[0].kind == "text_match"
    assert rows[0].value["line"] == 1


def test_apktool_inventory_classifies_manifest_and_smali(tmp_path):
    out = tmp_path / "work" / "apktool"
    (out / "smali").mkdir(parents=True)
    (out / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")
    (out / "smali" / "A.smali").write_text(".class A", encoding="utf-8")
    provider = ApktoolReadProvider(tmp_path / "app.apk", tmp_path / "work", FakeRunner())
    rows = provider.observe("ARTIFACT_INDEX", None)
    kinds = {r.kind for r in rows}
    assert "manifest" in kinds and "smali_file" in kinds


def test_adapter_surface_exposes_no_patch_or_rebuild_capability(tmp_path):
    providers = [
        Radare2ReadProvider(tmp_path / "x.so", FakeRunner()),
        JadxReadProvider(tmp_path / "x.apk", tmp_path / "w", FakeRunner()),
        ApktoolReadProvider(tmp_path / "x.apk", tmp_path / "w", FakeRunner()),
    ]
    for provider in providers:
        assert not provider.supports("PATCH_COMMIT")
        assert not provider.supports("REBUILD")
        assert not provider.supports("SIGN")
