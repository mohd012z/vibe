import json
import zipfile
from pathlib import Path

import pytest

from tools.apk_pipeline import ApkPipeline, PipelineError, Stage


def make_apk(tmp_path: Path) -> Path:
    apk = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("AndroidManifest.xml", b"binary-manifest-placeholder")
        z.writestr("classes.dex", b"dex\n035\x00")
        z.writestr("lib/arm64-v8a/libdemo.so", b"\x7fELF")
    return apk


def test_inspect_creates_hashed_run_and_inventory(tmp_path):
    apk = make_apk(tmp_path)
    p = ApkPipeline(apk, runs_root=tmp_path / "runs")
    result = p.inspect()

    assert result.stage == Stage.INSPECT
    assert result.ok is True
    inventory = json.loads((p.run_dir / "inventory.json").read_text())
    assert inventory["sha256"] == p.sha256
    assert inventory["dex_files"] == ["classes.dex"]
    assert inventory["native_libs"] == ["lib/arm64-v8a/libdemo.so"]


def test_extract_is_read_only_and_records_outputs(tmp_path):
    apk = make_apk(tmp_path)
    before = apk.read_bytes()
    p = ApkPipeline(apk, runs_root=tmp_path / "runs")
    result = p.extract()

    assert result.ok is True
    assert apk.read_bytes() == before
    assert (p.run_dir / "extracted" / "classes.dex").exists()
    assert result.output_hashes


def test_mutating_stage_requires_authorization(tmp_path):
    apk = make_apk(tmp_path)
    p = ApkPipeline(apk, runs_root=tmp_path / "runs")

    with pytest.raises(PipelineError, match="authorization"):
        p.require_authorization(Stage.REBUILD, None)

    p.require_authorization(Stage.REBUILD, "rights held: test fixture")


def test_stage_record_contains_provenance(tmp_path):
    apk = make_apk(tmp_path)
    p = ApkPipeline(apk, runs_root=tmp_path / "runs")
    result = p.inspect()
    record = json.loads((p.run_dir / "stages" / "inspect.json").read_text())

    assert record["stage"] == "inspect"
    assert record["input_sha256"] == p.sha256
    assert record["ok"] is True
    assert "started_at" in record
    assert "finished_at" in record
    assert record["outputs"] == result.outputs
