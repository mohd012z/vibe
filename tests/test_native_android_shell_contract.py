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
    assert "android.permission.FOREGROUND_SERVICE_SPECIAL_USE" in manifest
    assert 'android:foregroundServiceType="specialUse"' in manifest
    assert 'android:exported="false"' in manifest
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

def test_emulator_smoke_runs_in_one_persistent_shell():
    """The emulator runner executes YAML script lines in separate shells."""
    import subprocess

    workflow = (ROOT / ".github/workflows/android-apk.yml").read_text()
    script = ROOT / "scripts/emulator-smoke.sh"
    assert "script: bash scripts/emulator-smoke.sh" in workflow
    assert script.is_file()
    body = script.read_text()
    assert "set -euo pipefail" in body
    assert "cd android-app" in body
    assert 'adb install -r "$APK"' in body
    # LiveTestService is intentionally android:exported="false". Starting it
    # from the ADB shell is rejected by Android; use the app's own UI instead.
    assert "adb shell am start-foreground-service" not in body
    assert not re.search(r"^adb\\s+shell\\s+am\\s+startservice\\b", body, re.MULTILINE)
    assert "adb shell input tap" in body
    assert "locate_live_test_button.py" in body
    assert 'tap 150 350' not in body
    assert "BUTTON_FOUND" in body
    assert (ROOT / "scripts/locate_live_test_button.py").is_file()
    activity = (APP / "app/src/main/java/com/vibe/app/MainActivity.kt").read_text()
    manifest = (APP / "app/src/main/AndroidManifest.xml").read_text()
    assert 'android:exported="false"' in manifest
    assert "startLiveService()" in activity
    assert "ContextCompat.startForegroundService(this, intent)" in activity
    assert subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True).returncode == 0
