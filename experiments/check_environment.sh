#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
OUT="$ROOT/results/environment.txt"

mkdir -p "$ROOT/results"

resolve_tool() {
  CANDIDATE="$1"
  COMMAND_NAME="$2"
  FALLBACK_PATH="${3:-}"

  if [ -n "$CANDIDATE" ] && [ -x "$CANDIDATE" ]; then
    printf '%s\n' "$CANDIDATE"
    return 0
  fi
  if [ -n "$COMMAND_NAME" ] && command -v "$COMMAND_NAME" >/dev/null 2>&1; then
    command -v "$COMMAND_NAME"
    return 0
  fi
  if [ -n "$FALLBACK_PATH" ] && [ -x "$FALLBACK_PATH" ]; then
    printf '%s\n' "$FALLBACK_PATH"
    return 0
  fi
  return 1
}

resolve_java() {
  if [ -n "${JAVA_BIN:-}" ] && [ -x "${JAVA_BIN:-}" ]; then
    printf '%s\n' "${JAVA_BIN}"
    return 0
  fi
  if [ -n "${JAVA_HOME:-}" ] && [ -x "${JAVA_HOME}/bin/java" ]; then
    printf '%s\n' "${JAVA_HOME}/bin/java"
    return 0
  fi
  if command -v java >/dev/null 2>&1; then
    command -v java
    return 0
  fi
  return 1
}

java_major_version() {
  JAVA_PATH="$1"
  VERSION_LINE="$("$JAVA_PATH" -version 2>&1 | awk -F'"' '/version/ {print $2; exit}')"
  if [ -z "$VERSION_LINE" ]; then
    return 1
  fi
  MAJOR="${VERSION_LINE%%.*}"
  if [ "$MAJOR" = "1" ]; then
    MAJOR="$(printf '%s\n' "$VERSION_LINE" | cut -d. -f2)"
  fi
  printf '%s\n' "$MAJOR"
}

JAVA_BIN_RESOLVED="$(resolve_java || true)"
MAVEN_BIN_RESOLVED="$(resolve_tool "${MAVEN_BIN:-}" "mvn" "" || true)"
RUSTC_BIN_RESOLVED="$(resolve_tool "${RUSTC_BIN:-}" "rustc" "" || true)"
CARGO_BIN_RESOLVED="$(resolve_tool "${CARGO_BIN:-}" "cargo" "" || true)"
OPENSSL_BIN_RESOLVED="$(resolve_tool "${OPENSSL_BIN:-}" "openssl" "" || true)"

JAVA_STATUS="missing"
MAVEN_STATUS="missing"
RUST_STATUS="missing"
CARGO_STATUS="missing"
OPENSSL_STATUS="missing"

[ -n "$JAVA_BIN_RESOLVED" ] && JAVA_STATUS="ok"
[ -n "$MAVEN_BIN_RESOLVED" ] && MAVEN_STATUS="ok"
[ -n "$RUSTC_BIN_RESOLVED" ] && RUST_STATUS="ok"
[ -n "$CARGO_BIN_RESOLVED" ] && CARGO_STATUS="ok"
[ -n "$OPENSSL_BIN_RESOLVED" ] && OPENSSL_STATUS="ok"

BASELINE_JAVA_BIN="$JAVA_BIN_RESOLVED"
if [ -n "${JAVA_HOME:-}" ] && [ -x "${JAVA_HOME}/bin/java" ]; then
  JAVA_HOME_BIN="${JAVA_HOME}/bin/java"
  JAVA_HOME_MAJOR="$(java_major_version "$JAVA_HOME_BIN" || true)"
  if [ -n "$JAVA_HOME_MAJOR" ] && [ "$JAVA_HOME_MAJOR" -ge 17 ]; then
    BASELINE_JAVA_BIN="$JAVA_HOME_BIN"
  fi
fi
if [ -n "$BASELINE_JAVA_BIN" ]; then
  JAVA_MAJOR="$(java_major_version "$BASELINE_JAVA_BIN" || true)"
  if [ -n "$JAVA_MAJOR" ] && [ "$JAVA_MAJOR" -lt 17 ]; then
    BASELINE_JAVA_BIN=""
  fi
fi

JZLINT_SNAPSHOT="$ROOT/third_party/jzlint-main"
JZLINT_JAR="$JZLINT_SNAPSHOT/jzlint-cli/target/jzlint-cli-2.0.1.jar"
BASELINE_EXECUTABLE="$JZLINT_SNAPSHOT/jlint-pqc/src/main/resources/cli.exe"
BRIDGE_MANIFEST="$ROOT/tools/libcrux_import_check/Cargo.toml"
APPENDIX_SNAPSHOT="$ROOT/third_party/pqc-certificates-main"

BASELINE_REPLAY_STATUS="blocked"
if [ -n "$BASELINE_JAVA_BIN" ] && [ -f "$BASELINE_EXECUTABLE" ]; then
  if [ -f "$JZLINT_JAR" ] || { [ "$MAVEN_STATUS" = "ok" ] && [ -d "$JZLINT_SNAPSHOT" ]; }; then
    BASELINE_REPLAY_STATUS="ready"
  fi
fi

BRIDGE_BUILD_STATUS="blocked"
if [ "$CARGO_STATUS" = "ok" ] && [ -f "$BRIDGE_MANIFEST" ]; then
  BRIDGE_BUILD_STATUS="ready"
fi

APPENDIX_REPLAY_STATUS="blocked"
if [ -d "$APPENDIX_SNAPSHOT" ]; then
  APPENDIX_REPLAY_STATUS="ready"
fi

ENVIRONMENT_STATUS="degraded"
if [ "$JAVA_STATUS" = "ok" ] && [ "$MAVEN_STATUS" = "ok" ] && [ "$RUST_STATUS" = "ok" ] \
  && [ "$CARGO_STATUS" = "ok" ] && [ "$OPENSSL_STATUS" = "ok" ]; then
  ENVIRONMENT_STATUS="ok"
fi

{
  echo "# Environment check"
  echo "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "root=."
  echo "java_status=$JAVA_STATUS"
  [ -n "$JAVA_BIN_RESOLVED" ] && echo "java_bin=$JAVA_BIN_RESOLVED"
  echo "maven_status=$MAVEN_STATUS"
  [ -n "$MAVEN_BIN_RESOLVED" ] && echo "maven_bin=$MAVEN_BIN_RESOLVED"
  echo "rust_status=$RUST_STATUS"
  [ -n "$RUSTC_BIN_RESOLVED" ] && echo "rustc_bin=$RUSTC_BIN_RESOLVED"
  echo "cargo_status=$CARGO_STATUS"
  [ -n "$CARGO_BIN_RESOLVED" ] && echo "cargo_bin=$CARGO_BIN_RESOLVED"
  echo "openssl_status=$OPENSSL_STATUS"
  [ -n "$OPENSSL_BIN_RESOLVED" ] && echo "openssl_bin=$OPENSSL_BIN_RESOLVED"
  echo "baseline_replay_status=$BASELINE_REPLAY_STATUS"
  [ -n "$BASELINE_JAVA_BIN" ] && echo "baseline_java_bin=$BASELINE_JAVA_BIN"
  echo "bridge_build_status=$BRIDGE_BUILD_STATUS"
  echo "appendix_replay_status=$APPENDIX_REPLAY_STATUS"
  echo "environment_status=$ENVIRONMENT_STATUS"
  echo
  echo "## Versions"
  if [ -n "$JAVA_BIN_RESOLVED" ]; then
    "$JAVA_BIN_RESOLVED" -version 2>&1
  else
    echo "java: missing"
  fi
  echo
  if [ -n "$MAVEN_BIN_RESOLVED" ]; then
    "$MAVEN_BIN_RESOLVED" -version 2>&1
  else
    echo "mvn: missing"
  fi
  echo
  if [ -n "$RUSTC_BIN_RESOLVED" ]; then
    "$RUSTC_BIN_RESOLVED" --version
  else
    echo "rustc: missing"
  fi
  if [ -n "$CARGO_BIN_RESOLVED" ]; then
    "$CARGO_BIN_RESOLVED" --version
  else
    echo "cargo: missing"
  fi
  echo
  if command -v python3 >/dev/null 2>&1; then
    python3 --version
  else
    echo "python3: missing"
  fi
  echo
  if [ -n "$OPENSSL_BIN_RESOLVED" ]; then
    "$OPENSSL_BIN_RESOLVED" version
  else
    echo "openssl: missing"
  fi
} > "$OUT"

cat "$OUT"

if [ "${STRICT_ENV:-0}" = "1" ] && [ "$ENVIRONMENT_STATUS" != "ok" ]; then
  exit 1
fi
