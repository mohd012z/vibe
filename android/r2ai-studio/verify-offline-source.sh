#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
command -v javac >/dev/null || { echo "BLOCKED: javac unavailable" >&2; exit 2; }
command -v java >/dev/null || { echo "BLOCKED: java unavailable" >&2; exit 2; }
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
find src/main/java src/test/java -name '*.java' -print0 | xargs -0 javac -d "$out"
for suite in org.r2aistudio.offline.OperationGateTest org.r2aistudio.offline.BoundedReaderTest org.r2aistudio.offline.OfflineInspectorTest; do
  java -cp "$out" "$suite"
done
echo "PASS: 3 staged offline JVM suites"
if [[ ! -d android-app ]]; then
  echo "BLOCKED: Android application source not yet staged; no APK build attempted" >&2
  exit 4
fi
if [[ -z "${ANDROID_HOME:-}" && -z "${ANDROID_SDK_ROOT:-}" ]]; then
  echo "BLOCKED: Android SDK not configured" >&2
  exit 5
fi
echo "Android SDK configured; run a real Gradle build before declaring an APK verified."
