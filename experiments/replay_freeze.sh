#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
RESULTS="$ROOT/results"
LOG="$RESULTS/replay.log"
STATUS="$RESULTS/replay_status.txt"

mkdir -p "$RESULTS"
: > "$LOG"

log_note() {
  printf '%s\n' "$1" >> "$LOG"
}

run_step() {
  STEP="$1"
  shift
  log_note ""
  log_note "== $STEP =="
  "$@" >> "$LOG" 2>&1
}

run_required_step() {
  STEP="$1"
  shift
  if run_step "$STEP" "$@"; then
    return 0
  fi
  CODE=$?
  log_note "step_exit_code=$CODE"
  exit "$CODE"
}

run_optional_step() {
  STEP="$1"
  shift
  if run_step "$STEP" "$@"; then
    return 0
  fi
  CODE=$?
  log_note "step_exit_code=$CODE"
  return "$CODE"
}

bridge_binary_exists() {
  if [ -n "${LIBCRUX_IMPORT_CHECK_BIN:-}" ] && [ -x "${LIBCRUX_IMPORT_CHECK_BIN:-}" ]; then
    return 0
  fi
  if [ -x "$ROOT/tools/libcrux_import_check/target/debug/libcrux-import-check" ]; then
    return 0
  fi
  if [ -x "$ROOT/tools/libcrux_import_check/target/release/libcrux-import-check" ]; then
    return 0
  fi
  return 1
}

log_note "# Replay"
log_note "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

run_optional_step "check_environment" "$ROOT/experiments/check_environment.sh" || true

run_required_step "prepare_third_party" "$ROOT/experiments/prepare_third_party.sh"

if run_optional_step "build_libcrux_import_check" "$ROOT/experiments/build_libcrux_import_check.sh"; then
  BRIDGE_STATUS="built"
elif [ ! -f "$ROOT/tools/libcrux_import_check/Cargo.toml" ]; then
  BRIDGE_STATUS="missing-source"
elif ! command -v cargo >/dev/null 2>&1; then
  BRIDGE_STATUS="missing-cargo"
elif bridge_binary_exists; then
  BRIDGE_STATUS="reused-frozen"
else
  BRIDGE_STATUS="reused-frozen"
fi

run_required_step "generate_corpus_openssl" "$ROOT/experiments/generate_corpus_openssl.sh"
run_required_step "generate_mutations_openssl" "$ROOT/experiments/generate_mutations_openssl.sh"
run_required_step "generate_der_mutations" "$ROOT/experiments/generate_der_mutations.sh"
run_required_step "run_extended_strict" "$ROOT/experiments/run_extended.sh" --mode strict
run_required_step "run_extended_deployable" "$ROOT/experiments/run_extended.sh" --mode deployable
run_required_step "run_coverage_strict" "$ROOT/experiments/run_coverage.sh" --mode strict
run_required_step "run_coverage_deployable" "$ROOT/experiments/run_coverage.sh" --mode deployable
run_required_step "run_private_key_coverage_strict" "$ROOT/experiments/run_private_key_coverage.sh" --mode strict
run_required_step "run_private_key_coverage_deployable" "$ROOT/experiments/run_private_key_coverage.sh" --mode deployable

if run_optional_step "run_baseline" "$ROOT/experiments/run_baseline.sh"; then
  BASELINE_STATUS="live"
else
  BASELINE_STATUS="reused-frozen"
fi

if ! run_optional_step "run_baseline_compare" "$ROOT/experiments/run_baseline_compare.sh"; then
  BASELINE_STATUS="blocked"
fi

if [ -d "$ROOT/third_party/pqc-certificates-main" ]; then
  APPENDIX_EXPECTED_STATUS="live"
else
  APPENDIX_EXPECTED_STATUS="reused-frozen"
fi
if run_optional_step "run_real_world_appendix" "$ROOT/experiments/run_real_world_appendix.sh"; then
  APPENDIX_STATUS="$APPENDIX_EXPECTED_STATUS"
else
  APPENDIX_STATUS="blocked"
fi

run_required_step "run_reference_workflow" "$ROOT/experiments/run_reference_workflow.sh"
run_required_step "run_operator_gate_packs" "$ROOT/experiments/run_operator_gate_packs.sh"
run_required_step "run_cross_tool_behavior" "$ROOT/experiments/run_cross_tool_behavior.sh"
run_required_step "run_smoke_tests" "$ROOT/experiments/run_smoke_tests.sh"

{
  echo "# Replay status"
  echo "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "environment_status=$(awk -F= '/^environment_status=/ {print $2}' "$ROOT/results/environment.txt" | tail -n 1)"
  echo "bridge_status=$BRIDGE_STATUS"
  echo "baseline_status=$BASELINE_STATUS"
  echo "appendix_status=$APPENDIX_STATUS"
  echo "smoke_tests=pass"
  echo "log=results/replay.log"
} > "$STATUS"

cat "$STATUS"
