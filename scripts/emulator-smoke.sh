#!/usr/bin/env bash
# Run as a single shell process: android-emulator-runner executes YAML script lines separately.
set -euo pipefail

cd android-app
gradle --no-daemon --console=plain :app:assembleDebug
APK=app/build/outputs/apk/debug/app-debug.apk
test -s "$APK"
adb install -r "$APK"
adb shell cmd package resolve-activity --brief com.vibe.app > /tmp/vibe-resolved.txt
cat /tmp/vibe-resolved.txt
adb logcat -c
adb shell am start -W -n com.vibe.app/.MainActivity > /tmp/vibe-launch.txt
cat /tmp/vibe-launch.txt
sleep 2
adb shell pidof -s com.vibe.app > /tmp/vibe-pid.txt
cat /tmp/vibe-pid.txt
adb shell dumpsys activity activities | grep -F 'com.vibe.app/.MainActivity'
# The service is private: start it using an exact visible, app-owned UI
# button. Hard-coded pixels tapped the wrong control on a 420-dpi emulator.
# Never use ADB am startservice against android:exported="false".
BUTTON_FOUND=0
for attempt in 1 2 3; do
  adb shell uiautomator dump /sdcard/vibe-window.xml >/dev/null 2>&1 || true
  adb exec-out cat /sdcard/vibe-window.xml > /tmp/vibe-window.xml || true
  if python3 ../scripts/locate_live_test_button.py /tmp/vibe-window.xml > /tmp/vibe-button-coordinates.txt; then
    BUTTON_FOUND=1
    break
  fi
  sleep 2
done
if [ "$BUTTON_FOUND" -ne 1 ]; then
  echo "Live Test button was not visible; refusing to tap blindly." >&2
  exit 1
fi
read -r BUTTON_X BUTTON_Y < /tmp/vibe-button-coordinates.txt
adb shell input tap "$BUTTON_X" "$BUTTON_Y"
sleep 3
adb shell dumpsys activity services com.vibe.app > /tmp/vibe-services.txt
cat /tmp/vibe-services.txt
grep -F 'LiveTestService' /tmp/vibe-services.txt
adb logcat -b crash -d > /tmp/vibe-crash.txt
cat /tmp/vibe-crash.txt
if grep -E 'FATAL EXCEPTION|Process: com\.vibe\.app' /tmp/vibe-crash.txt; then
  echo 'Vibe crash detected' >&2
  exit 1
fi
