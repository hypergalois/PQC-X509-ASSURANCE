#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$ROOT/src"

cd "$ROOT"
python3 -B -m unittest discover -s tests -p 'test_*.py'
