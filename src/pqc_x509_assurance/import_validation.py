"""Small wrappers for import-validation checks that depend on libcrux."""

from __future__ import annotations

import subprocess
from pathlib import Path

from .host_tools import discover_import_bridge_binary


ROOT = Path(__file__).resolve().parents[2]
BRIDGE_MANIFEST = ROOT / "tools" / "libcrux_import_check" / "Cargo.toml"
BRIDGE_BINARY = ROOT / "tools" / "libcrux_import_check" / "target" / "debug" / "libcrux-import-check"
BRIDGE_BINARY_RELEASE = ROOT / "tools" / "libcrux_import_check" / "target" / "release" / "libcrux-import-check"


def resolve_bridge_binary() -> Path | None:
    return discover_import_bridge_binary(ROOT)


def check_seed_expanded_consistency(
    parameter_set: str,
    seed: bytes,
    expanded_key: bytes,
) -> tuple[bool, str]:
    bridge_binary = resolve_bridge_binary()
    if bridge_binary is None:
        raise ValueError(
            "libcrux import bridge is not available; add or build the bridge before enabling seed/expanded consistency checks"
        )
    completed = subprocess.run(
        [
            str(bridge_binary),
            "consistency",
            parameter_set,
            seed.hex(),
            expanded_key.hex(),
        ],
        text=True,
        capture_output=True,
        check=False,
        cwd=ROOT,
    )
    stdout = completed.stdout.strip()
    stderr = completed.stderr.strip()
    if completed.returncode == 0:
        return True, stdout or "match"
    if completed.returncode == 1:
        return False, stdout or "mismatch"
    detail = stderr or stdout or f"bridge exited with status {completed.returncode}"
    raise ValueError(f"libcrux import bridge failed: {detail}")
