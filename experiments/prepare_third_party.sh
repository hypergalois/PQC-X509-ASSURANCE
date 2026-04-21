#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
DEST="$ROOT/third_party"
REF=""

if [ -d "$ROOT/reference/github" ]; then
  REF="$ROOT/reference/github"
elif [ -d "$ROOT/../reference/github" ]; then
  REF="$ROOT/../reference/github"
fi

mkdir -p "$DEST"

restore_or_reuse() {
  NAME="$1"
  OUTDIR="$2"
  ZIP="$3"

  if [ -d "$OUTDIR" ]; then
    echo "reusing vendored snapshot $OUTDIR"
    return 0
  fi

  if [ -n "$ZIP" ] && [ -f "$ZIP" ]; then
    echo "restoring frozen snapshot from reference/github for $NAME"
    unzip -q "$ZIP" -d "$DEST"
    if [ ! -d "$OUTDIR" ]; then
      echo "Failed to restore $NAME into $OUTDIR" >&2
      exit 1
    fi
    return 0
  fi

  echo "Missing vendored snapshot and frozen archive for $NAME" >&2
  exit 1
}

if [ -n "$REF" ]; then
  JZLINT_ZIP="$REF/jzlint-main.zip"
  LIBCRUX_ZIP="$REF/libcrux-main.zip"
  PQCERT_ZIP="$REF/pqc-certificates-main.zip"
else
  JZLINT_ZIP=""
  LIBCRUX_ZIP=""
  PQCERT_ZIP=""
fi

restore_or_reuse "jzlint-main" "$DEST/jzlint-main" "$JZLINT_ZIP"
restore_or_reuse "libcrux-main" "$DEST/libcrux-main" "$LIBCRUX_ZIP"

if [ -d "$DEST/pqc-certificates-main" ]; then
  echo "reusing vendored snapshot $DEST/pqc-certificates-main"
elif [ -n "$PQCERT_ZIP" ] && [ -f "$PQCERT_ZIP" ]; then
  echo "restoring frozen snapshot from reference/github for pqc-certificates-main"
  unzip -q "$PQCERT_ZIP" -d "$DEST"
  [ -d "$DEST/pqc-certificates-main" ]
else
  echo "note: public appendix replay is frozen-only unless pqc-certificates-main is supplied separately"
fi
