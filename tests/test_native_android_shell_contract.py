from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "android-app"


def test_native_android_project_exists():
    assert (APP / "settings.gradle.kts").is_file()
    assert (APP / "build.gradle.kts").is_file()
    assert (APP / "app" / "build.gradle.kts").is_file()


def test_manifest_declares_launcher_and_foreground_live_test_service():
    manifest = (APP / "app/src/main/AndroidManifest.xml").read_text()
    assert "android.intent.action.MAIN" in manifest
    assert "android.intent.category.LAUNCHER" in manifest
    assert ".LiveTestService" in manifest
    assert "android.permission.FOREGROUND_SERVICE" in manifest
    assert "android.permission.SYSTEM_ALERT_WINDOW" not in manifest


def test_home_exposes_three_test_modes():
    source = (APP / "app/src/main/java/com/vibe/app/MainActivity.kt").read_text()
    for label in ("Test Installed App", "Test APK File", "Live Test"):
        assert label in source


def test_live_service_has_explicit_runtime_actions():
    source = (APP / "app/src/main/java/com/vibe/app/LiveTestService.kt").read_text()
    for action in ("ACTION_MARK_ISSUE", "ACTION_SNAPSHOT", "ACTION_PAUSE_RESUME", "ACTION_STOP"):
        assert action in source
    assert "startForeground" in source


def test_no_private_memory_or_hidden_evasion_contracts():
    combined = "\n".join(
        p.read_text(errors="ignore")
        for p in (APP / "app/src/main").rglob("*")
        if p.is_file()
    ).lower()
    forbidden = ("/proc/", "ptrace", "private_memory", "hide process", "play protect bypass")
    assert not any(term in combined for term in forbidden)


def test_apk_file_mode_uses_android_document_picker():
    source = (APP / "app/src/main/java/com/vibe/app/MainActivity.kt").read_text()
    assert "OpenDocument" in source
    assert "application/vnd.android.package-archive" in source
