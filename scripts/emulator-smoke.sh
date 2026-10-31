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
adb shell am start-foreground-service -n com.vibe.app/.LiveTestService -a com.vibe.app.START
sleep 2
adb shell dumpsys activity services com.vibe.app > /tmp/vibe-services.txt
cat /tmp/vibe-services.txt
grep -F 'LiveTestService' /tmp/vibe-services.txt
adb shell am startservice -n com.vibe.app/.LiveTestService -a com.vibe.app.MARK_ISSUE
adb shell am startservice -n com.vibe.app/.LiveTestService -a com.vibe.app.SNAPSHOT
adb shell am startservice -n com.vibe.app/.LiveTestService -a com.vibe.app.PAUSE_RESUME
adb shell am startservice -n com.vibe.app/.LiveTestService -a com.vibe.app.STOP
sleep 1
adb shell dumpsys activity services com.vibe.app > /tmp/vibe-services-after-stop.txt
cat /tmp/vibe-services-after-stop.txt
if grep -Fq 'LiveTestService' /tmp/vibe-services-after-stop.txt; then
  echo 'LiveTestService still active after STOP' >&2
  exit 1
fi
adb logcat -b crash -d > /tmp/vibe-crash.txt
cat /tmp/vibe-crash.txt
if grep -E 'FATAL EXCEPTION|Process: com\.vibe\.app' /tmp/vibe-crash.txt; then
  echo 'Vibe crash detected' >&2
  exit 1
fi
