#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
JZLINT="${JZLINT_SNAPSHOT:-$ROOT/third_party/jzlint-main}"
JAR="$JZLINT/jzlint-cli/target/jzlint-cli-2.0.1.jar"

mkdir -p "$ROOT/results"

if [ ! -d "$JZLINT" ]; then
  echo "Missing JZLint snapshot. Run ./experiments/prepare_third_party.sh or set JZLINT_SNAPSHOT." >&2
  exit 1
fi

if ! command -v mvn >/dev/null 2>&1; then
  echo "Maven is missing; cannot run JZLint baseline tests." >&2
  exit 1
fi

TEST_STATUS=0
(
  cd "$JZLINT"
  mvn -Dmaven.repo.local="$ROOT/.m2/repository" -pl jlint-pqc -am test
) || TEST_STATUS=$?

(
  cd "$JZLINT"
  if [ -f "$JAR" ]; then
    echo "reusing $JAR"
  else
    mvn -Dmaven.repo.local="$ROOT/.m2/repository" -pl jzlint-cli -am -DskipTests package
    [ -f "$JAR" ]
    echo "built $JAR"
  fi
)

exit "$TEST_STATUS"
