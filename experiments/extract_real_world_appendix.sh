#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$ROOT/src"

APPENDIX_ACCESS_DATE="${APPENDIX_ACCESS_DATE:-2026-04-15}"

if [ ! -d "$ROOT/third_party/pqc-certificates-main" ]; then
  echo "Missing frozen pqc-certificates snapshot at $ROOT/third_party/pqc-certificates-main"
  echo "The bounded appendix depends on that local snapshot; restore it before regenerating the appendix outputs."
  exit 1
fi

python3 -B -m pqc_x509_assurance.real_world_appendix \
  --root "$ROOT" \
  --extract \
  --access-date "$APPENDIX_ACCESS_DATE" \
  --manifest "$ROOT/corpus/appendix/manifest.jsonl" \
  --ledger "$ROOT/docs/real-world-appendix-ledger.md"
