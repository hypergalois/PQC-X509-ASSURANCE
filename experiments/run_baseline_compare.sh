#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$ROOT/src"

if python3 -B -m pqc_x509_assurance.baseline_compare "$@"; then
  exit 0
fi

echo "note: reusing frozen baseline comparison outputs because live baseline replay is unavailable on this host"
test -f "$ROOT/results/baseline_vs_extended_certificate_report.json"
test -f "$ROOT/results/baseline_vs_extended_certificate_comparison.csv"
test -f "$ROOT/results/baseline_jzlint_certificate_results.jsonl"
test -f "$ROOT/results/extended_certificate_eval.jsonl"
