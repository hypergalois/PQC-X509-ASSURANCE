"""Path helpers shared across artifact modules."""

from __future__ import annotations

from pathlib import Path


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def project_relpath(path: Path, root: Path | None = None) -> str:
    base = (root or project_root()).resolve()
    try:
        return str(path.resolve().relative_to(base))
    except ValueError:
        return str(path)
