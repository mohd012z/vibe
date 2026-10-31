#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
echo "R2AI Studio offline source preflight"
if [[ ! -d src/main/java || ! -d src/test/java ]]; then
  echo "BLOCKED: M14 portable Java sources have not yet been staged" >&2
  exit 2
fi
if ! command -v javac >/dev/null 2>&1; then
  echo "BLOCKED: JDK javac unavailable" >&2
  exit 3
fi
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
find src/main/java src/test/java -name '*.java' -print0 | xargs -0 javac -d "$out"
for suite in  org.r2aistudio.bridge.BridgeTest  org.r2aistudio.bridge.ProcessTransportTest  org.r2aistudio.editor.DocumentSessionTest  org.r2aistudio.editor.DocumentIOTest  org.r2aistudio.offline.OfflineInspectorTest  org.r2aistudio.offline.BoundedReaderTest  org.r2aistudio.offline.OperationGateTest; do
  java -cp "$out" "$suite"
done
echo "PASS: 7 JVM suites"
if [[ ! -d android-app ]]; then
  echo "BLOCKED: Android application source not yet staged"
  exit 4
fi
if [[ -z "${ANDROID_HOME:-}" && -z "${ANDROID_SDK_ROOT:-}" ]]; then
  echo "BLOCKED: Android SDK not configured"
  exit 5
fi
echo "Android source/toolchain detected; APK compilation must be verified separately."
