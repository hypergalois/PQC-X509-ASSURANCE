#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
MANIFEST="$ROOT/tools/libcrux_import_check/Cargo.toml"

if [ ! -f "$MANIFEST" ]; then
  echo "libcrux import bridge source is not bundled in this package"
  exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is required to build the libcrux import bridge"
  exit 1
fi

cargo build --quiet --locked --manifest-path "$MANIFEST"

echo "built $ROOT/tools/libcrux_import_check/target/debug/libcrux-import-check"
