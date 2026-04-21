"""Host tool discovery and build helpers for live replay."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict


JZLINT_SNAPSHOT_RELPATH = Path("third_party/jzlint-main")
JZLINT_JAR_RELPATH = JZLINT_SNAPSHOT_RELPATH / "jzlint-cli" / "target" / "jzlint-cli-2.0.1.jar"
BASELINE_EXECUTABLE_RELPATH = (
    JZLINT_SNAPSHOT_RELPATH / "jlint-pqc" / "src" / "main" / "resources" / "cli.exe"
)
BRIDGE_DEBUG_RELPATH = Path("tools/libcrux_import_check/target/debug/libcrux-import-check")
BRIDGE_RELEASE_RELPATH = Path("tools/libcrux_import_check/target/release/libcrux-import-check")


def _existing_path(*candidates: Path | str | None) -> Path | None:
    for candidate in candidates:
        if candidate is None:
            continue
        path = Path(candidate).expanduser()
        if path.exists():
            return path.resolve()
    return None


def _existing_executable(*candidates: Path | str | None) -> Path | None:
    for candidate in candidates:
        if candidate is None:
            continue
        path = Path(candidate).expanduser()
        if path.exists() and os.access(path, os.X_OK):
            return path.resolve()
    return None


def _which(command: str) -> Path | None:
    resolved = shutil.which(command)
    return Path(resolved).resolve() if resolved else None


def _java_home_candidate() -> Path | None:
    java_home = os.environ.get("JAVA_HOME")
    if not java_home:
        return None
    return _existing_executable(Path(java_home) / "bin" / "java")


def java_major_version(java_path: Path) -> int | None:
    process = subprocess.run(
        [str(java_path), "-version"],
        text=True,
        capture_output=True,
        check=False,
    )
    if process.returncode != 0:
        return None
    first_line = (process.stderr.strip() or process.stdout.strip()).splitlines()
    if not first_line:
        return None
    version_line = first_line[0]
    if '"' not in version_line:
        return None
    version_text = version_line.split('"')[1]
    parts = version_text.split(".")
    if not parts:
        return None
    if parts[0] == "1" and len(parts) > 1:
        return int(parts[1])
    return int(parts[0])


def discover_java_binary(explicit: Path | None = None, *, minimum_major: int | None = None) -> Path | None:
    candidates = [
        _existing_executable(explicit),
        _existing_executable(os.environ.get("JAVA_BIN")),
        _java_home_candidate(),
        _which("java"),
    ]
    for candidate in candidates:
        if candidate is None:
            continue
        if minimum_major is None:
            return candidate
        version = java_major_version(candidate)
        if version is not None and version >= minimum_major:
            return candidate
    return None


def discover_maven_binary(explicit: Path | None = None) -> Path | None:
    return _existing_executable(explicit, os.environ.get("MAVEN_BIN"), _which("mvn"))


def discover_rustc_binary(explicit: Path | None = None) -> Path | None:
    return _existing_executable(explicit, os.environ.get("RUSTC_BIN"), _which("rustc"))


def discover_cargo_binary(explicit: Path | None = None) -> Path | None:
    return _existing_executable(explicit, os.environ.get("CARGO_BIN"), _which("cargo"))


def discover_openssl_binary(explicit: Path | None = None) -> Path | None:
    return _existing_executable(explicit, os.environ.get("OPENSSL_BIN"), _which("openssl"))


def discover_pkilint_binary(explicit: Path | None = None) -> Path | None:
    return _existing_executable(explicit, os.environ.get("PKILINT_BIN"), _which("pkilint"))


def discover_jzlint_snapshot(root: Path, explicit: Path | None = None) -> Path | None:
    return _existing_path(explicit, os.environ.get("JZLINT_SNAPSHOT"), root / JZLINT_SNAPSHOT_RELPATH)


def default_jzlint_cli_jar(root: Path) -> Path:
    return (root / JZLINT_JAR_RELPATH).resolve()


def default_baseline_executable(root: Path) -> Path:
    return (root / BASELINE_EXECUTABLE_RELPATH).resolve()


def discover_jzlint_cli_jar(root: Path, explicit: Path | None = None) -> Path | None:
    return _existing_path(explicit, os.environ.get("JZLINT_CLI_JAR"), default_jzlint_cli_jar(root))


def discover_baseline_executable(root: Path, explicit: Path | None = None) -> Path | None:
    return _existing_path(
        explicit,
        os.environ.get("BASELINE_EXECUTABLE"),
        default_baseline_executable(root),
    )


def discover_import_bridge_binary(root: Path) -> Path | None:
    return _existing_executable(
        os.environ.get("LIBCRUX_IMPORT_CHECK_BIN"),
        root / BRIDGE_DEBUG_RELPATH,
        root / BRIDGE_RELEASE_RELPATH,
    )


def maven_available(explicit: Path | None = None) -> bool:
    return discover_maven_binary(explicit) is not None


def openssl_available(explicit: Path | None = None) -> bool:
    return discover_openssl_binary(explicit) is not None


def jzlint_cli_available(root: Path, explicit: Path | None = None) -> bool:
    return discover_jzlint_cli_jar(root, explicit) is not None


def baseline_host_status(
    root: Path,
    *,
    explicit_java: Path | None = None,
    explicit_jar: Path | None = None,
    explicit_executable: Path | None = None,
) -> Dict[str, Any]:
    java_path = discover_java_binary(explicit_java, minimum_major=17)
    jar_path = discover_jzlint_cli_jar(root, explicit_jar)
    executable_path = discover_baseline_executable(root, explicit_executable)
    snapshot_path = discover_jzlint_snapshot(root)
    maven_path = discover_maven_binary()

    available = java_path is not None and jar_path is not None and executable_path is not None
    build_possible = (
        java_path is not None
        and jar_path is None
        and executable_path is not None
        and snapshot_path is not None
        and maven_path is not None
    )

    if available:
        status = "available-certificate-only"
        reason = "baseline CLI is ready on this host"
    elif build_possible:
        status = "build-required"
        reason = "jzlint CLI jar is missing but vendored source plus Maven are available"
    else:
        missing = []
        if java_path is None:
            missing.append("java")
        if executable_path is None:
            missing.append("baseline executable")
        if jar_path is None:
            if snapshot_path is None:
                missing.append("jzlint snapshot")
            elif maven_path is None:
                missing.append("jzlint CLI jar and Maven")
            else:
                missing.append("jzlint CLI jar")
        status = "tool-unavailable-on-host"
        reason = "missing " + ", ".join(missing) if missing else "baseline CLI unavailable"

    return {
        "available": available,
        "status": status,
        "reason": reason,
        "build_possible": build_possible,
        "java_path": java_path,
        "jar_path": jar_path,
        "executable_path": executable_path,
        "snapshot_path": snapshot_path,
        "maven_path": maven_path,
    }


def build_jzlint_cli(
    root: Path,
    *,
    snapshot_path: Path | None = None,
    maven_path: Path | None = None,
) -> Dict[str, Any]:
    snapshot = snapshot_path or discover_jzlint_snapshot(root)
    maven = maven_path or discover_maven_binary()
    jar_path = default_jzlint_cli_jar(root)
    if snapshot is None:
        return {
            "success": False,
            "jar_path": None,
            "message": "vendored JZLint snapshot is missing",
        }
    if maven is None:
        return {
            "success": False,
            "jar_path": None,
            "message": "Maven is missing",
        }
    process = subprocess.run(
        [
            str(maven),
            f"-Dmaven.repo.local={root / '.m2' / 'repository'}",
            "-pl",
            "jzlint-cli",
            "-am",
            "-DskipTests",
            "package",
        ],
        cwd=snapshot,
        text=True,
        capture_output=True,
        check=False,
    )
    if process.returncode != 0 or not jar_path.exists():
        detail = process.stderr.strip() or process.stdout.strip() or "Maven build failed"
        return {
            "success": False,
            "jar_path": jar_path if jar_path.exists() else None,
            "message": detail,
        }
    return {
        "success": True,
        "jar_path": jar_path,
        "message": f"built {jar_path}",
    }
