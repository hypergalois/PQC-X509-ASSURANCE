#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$ROOT/src"

python3 -B -m pqc_x509_assurance.coverage_report \
  --stages private-key-container/import \
  --stem private_key_coverage \
  "$@"
