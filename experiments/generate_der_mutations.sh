#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$ROOT/src"

python3 -B -m pqc_x509_assurance.der_mutations --root "$ROOT"
python3 -B -m pqc_x509_assurance.corpus_manifest --root "$ROOT" --out "$ROOT/corpus/manifest.jsonl"

echo "generated deterministic DER mutations"
echo "updated $ROOT/corpus/manifest.jsonl"
