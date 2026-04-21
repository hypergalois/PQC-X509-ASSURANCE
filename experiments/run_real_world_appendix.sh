#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$ROOT/src"

APPENDIX_ACCESS_DATE="${APPENDIX_ACCESS_DATE:-2026-04-15}"

if [ -d "$ROOT/third_party/pqc-certificates-main" ]; then
  "$ROOT/experiments/extract_real_world_appendix.sh"

  python3 -B -m pqc_x509_assurance.run_extended \
    --manifest "$ROOT/corpus/appendix/manifest.jsonl" \
    --out-dir "$ROOT/results/appendix/extended"

  python3 -B -m pqc_x509_assurance.baseline_compare \
    --manifest "$ROOT/corpus/appendix/manifest.jsonl" \
    --out-dir "$ROOT/results/appendix/baseline_compare"

  exit 0
fi

echo "note: regenerating bounded appendix manifest and documentation from frozen appendix outputs"
python3 -B -m pqc_x509_assurance.real_world_appendix \
  --root "$ROOT" \
  --access-date "$APPENDIX_ACCESS_DATE" \
  --manifest "$ROOT/corpus/appendix/manifest.jsonl" \
  --ledger "$ROOT/docs/real-world-appendix-ledger.md" \
  --summary "$ROOT/results/appendix/appendix_coverage_summary.json" \
  --selection-rationale "$ROOT/docs/appendix-selection-rationale.md"

test -f "$ROOT/results/appendix/extended/extended_registry_summary.json"
test -f "$ROOT/results/appendix/baseline_compare/baseline_vs_extended_certificate_report.json"
