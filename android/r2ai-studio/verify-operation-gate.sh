#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
command -v javac >/dev/null || { echo "BLOCKED: javac missing" >&2; exit 2; }
command -v java >/dev/null || { echo "BLOCKED: java missing" >&2; exit 2; }
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
javac -d "$out" src/main/java/org/r2aistudio/offline/OperationGate.java src/test/java/org/r2aistudio/offline/OperationGateTest.java
java -cp "$out" org.r2aistudio.offline.OperationGateTest
