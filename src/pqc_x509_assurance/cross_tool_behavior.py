"""Build a bounded cross-tool behavior matrix for supporting evidence."""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence

from .baseline_compare import normalize_baseline_result, run_baseline_cli
from .host_tools import (
    baseline_host_status,
    discover_openssl_binary,
    discover_pkilint_binary,
)
from .paths import project_relpath
from .private_keys import lint_private_key_container_der
from .requirements import load_registry, requirements
from .run_extended import read_jsonl
from .x509 import DERError, lint_certificate_der, load_der


TOOL_ROWS = ("extended-local", "jzlint-baseline", "openssl-cli", "pkilint")
BEHAVIOR_VALUES = {
    "accepted",
    "rejected-structural",
    "rejected-semantic",
    "not-applicable",
    "runtime-failure",
    "tool-unavailable-on-host",
}


def _sanitize_tool_message(message: str, *, root: Path, artifact_path: Path | None = None) -> str:
    cleaned = message.strip()
    if artifact_path is not None:
        cleaned = cleaned.replace(str(artifact_path), project_relpath(artifact_path, root))
    cleaned = cleaned.replace(str(root), ".")
    return cleaned


def gather_cross_tool_artifacts(root: Path) -> List[Dict[str, Any]]:
    controlled = list(read_jsonl(root / "corpus" / "manifest.jsonl"))
    appendix = list(read_jsonl(root / "corpus" / "appendix" / "manifest.jsonl"))
    selected: List[Dict[str, Any]] = []
    for record in controlled:
        if record.get("artifact_type") not in {"certificate", "private-key-container"}:
            continue
        selected.append({**record, "source_set": "controlled"})
    for record in appendix:
        if record.get("artifact_type") not in {"certificate", "private-key-container"}:
            continue
        selected.append({**record, "source_set": "appendix"})
    return selected


def requirement_index(registry_path: Path) -> Dict[str, Dict[str, Any]]:
    return {
        str(requirement["id"]): requirement
        for requirement in requirements(load_registry(registry_path))
    }


def classify_requirement_ids(
    requirement_ids: Sequence[str],
    requirement_map: Mapping[str, Mapping[str, Any]],
) -> str:
    if not requirement_ids:
        return "accepted"
    detector_kinds = {
        str(requirement_map[requirement_id]["detector_kind"])
        for requirement_id in requirement_ids
        if requirement_id in requirement_map
    }
    if detector_kinds and detector_kinds <= {"structural"}:
        return "rejected-structural"
    return "rejected-semantic"


def run_extended_local_behavior(
    record: Mapping[str, Any],
    root: Path,
    requirement_map: Mapping[str, Mapping[str, Any]],
) -> Dict[str, Any]:
    artifact_path = root / str(record.get("path"))
    try:
        data = load_der(artifact_path)
        if record.get("artifact_type") == "certificate":
            findings = lint_certificate_der(data)
        elif record.get("artifact_type") == "private-key-container":
            findings = lint_private_key_container_der(data)
        else:
            return _base_behavior_row(record, "extended-local", "not-applicable", "policy-and-structural")
    except (DERError, ValueError) as exc:
        return _base_behavior_row(
            record,
            "extended-local",
            "rejected-structural",
            "policy-and-structural",
            message=_sanitize_tool_message(str(exc), root=root, artifact_path=artifact_path),
        )
    except OSError as exc:
        return _base_behavior_row(
            record,
            "extended-local",
            "runtime-failure",
            "policy-and-structural",
            message=_sanitize_tool_message(str(exc), root=root, artifact_path=artifact_path),
        )

    requirement_ids = sorted(
        {
            str(finding.get("requirement_id"))
            for finding in findings
            if str(finding.get("status")) == "error"
        }
    )
    behavior = classify_requirement_ids(requirement_ids, requirement_map)
    row = _base_behavior_row(
        record,
        "extended-local",
        behavior,
        "policy-and-structural",
        message="local extended detector evaluation",
    )
    row["requirement_ids"] = requirement_ids
    row["finding_count"] = len(requirement_ids)
    return row


def run_jzlint_behavior(
    record: Mapping[str, Any],
    root: Path,
    requirement_map: Mapping[str, Mapping[str, Any]],
    *,
    baseline_runtime: Mapping[str, Any],
) -> Dict[str, Any]:
    if record.get("artifact_type") != "certificate":
        return _base_behavior_row(record, "jzlint-baseline", "not-applicable", "policy-and-structural")
    if not baseline_runtime.get("available"):
        return _base_behavior_row(
            record,
            "jzlint-baseline",
            "tool-unavailable-on-host",
            "policy-and-structural",
            message=str(baseline_runtime.get("reason", "baseline CLI unavailable")),
        )
    artifact_path = root / str(record.get("path"))
    try:
        raw = run_baseline_cli(
            java_path=Path(baseline_runtime["java_path"]),
            jar_path=Path(baseline_runtime["jar_path"]),
            executable_path=Path(baseline_runtime["executable_path"]),
            certificate_path=artifact_path,
        )
        normalized = normalize_baseline_result(
            record,
            raw["raw_lint_results"],
            float(raw["elapsed_ms"]),
            str(raw["stderr"]),
        )
    except (RuntimeError, OSError) as exc:
        return _base_behavior_row(
            record,
            "jzlint-baseline",
            "runtime-failure",
            "policy-and-structural",
            message=_sanitize_tool_message(str(exc), root=root, artifact_path=artifact_path),
        )
    if normalized.get("status") == "fatal":
        return _base_behavior_row(
            record,
            "jzlint-baseline",
            "runtime-failure",
            "policy-and-structural",
            message="baseline returned fatal",
            requirement_ids=list(normalized.get("fatal_requirement_candidates", [])),
        )
    requirement_ids = list(normalized.get("detected_requirements", []))
    behavior = classify_requirement_ids(requirement_ids, requirement_map)
    row = _base_behavior_row(
        record,
        "jzlint-baseline",
        behavior,
        "policy-and-structural",
        message="baseline certificate-only behavior",
        requirement_ids=requirement_ids,
    )
    row["finding_count"] = len(requirement_ids)
    return row


def run_openssl_behavior(
    record: Mapping[str, Any],
    root: Path,
    openssl_path: Path | None,
) -> Dict[str, Any]:
    artifact_type = str(record.get("artifact_type"))
    if artifact_type not in {"certificate", "private-key-container"}:
        return _base_behavior_row(record, "openssl-cli", "not-applicable", "parse-only")
    if openssl_path is None:
        return _base_behavior_row(
            record,
            "openssl-cli",
            "tool-unavailable-on-host",
            "parse-only",
            message="openssl binary is unavailable on this host",
        )
    artifact_path = root / str(record.get("path"))
    command = [str(openssl_path)]
    if artifact_type == "certificate":
        command.extend(["x509", "-in", str(artifact_path), "-noout", "-text"])
    else:
        command.extend(["pkey", "-in", str(artifact_path), "-noout", "-text"])
    if artifact_path.suffix.lower() == ".der":
        command.extend(["-inform", "DER"])
    try:
        process = subprocess.run(command, capture_output=True, text=True, check=False)
    except OSError as exc:
        return _base_behavior_row(
            record,
            "openssl-cli",
            "tool-unavailable-on-host",
            "parse-only",
            message=str(exc),
        )
    if process.returncode == 0:
        return _base_behavior_row(
            record,
            "openssl-cli",
            "accepted",
            "parse-only",
            message="openssl parsed/imported artifact",
        )
    behavior = "runtime-failure" if record.get("validity") == "valid" else "rejected-structural"
    stderr = process.stderr.strip() or process.stdout.strip() or f"openssl exited {process.returncode}"
    return _base_behavior_row(
        record,
        "openssl-cli",
        behavior,
        "parse-only",
        message=_sanitize_tool_message(stderr, root=root, artifact_path=artifact_path),
    )


def run_pkilint_behavior(
    record: Mapping[str, Any],
    root: Path,
    pkilint_path: Path | None,
) -> Dict[str, Any]:
    del root
    if record.get("artifact_type") != "certificate":
        return _base_behavior_row(record, "pkilint", "not-applicable", "parse-only")
    if pkilint_path is None:
        return _base_behavior_row(
            record,
            "pkilint",
            "tool-unavailable-on-host",
            "parse-only",
            message="no pkilint binary is configured on this host",
        )
    return _base_behavior_row(
        record,
        "pkilint",
        "runtime-failure",
        "parse-only",
        message="pkilint is present on this host but is not wired into this workflow",
    )


def derive_tool_status(
    root: Path,
    *,
    java_path: Path | None,
    jar_path: Path | None,
    executable_path: Path | None,
) -> Dict[str, Any]:
    baseline_runtime = baseline_host_status(
        root,
        explicit_java=java_path,
        explicit_jar=jar_path,
        explicit_executable=executable_path,
    )
    openssl_path = discover_openssl_binary()
    pkilint_path = discover_pkilint_binary()
    return {
        "tool_status": {
            "extended-local": "available",
            "jzlint-baseline": str(baseline_runtime["status"]),
            "openssl-cli": "available-parse-only" if openssl_path else "tool-unavailable-on-host",
            "pkilint": "available-but-not-integrated" if pkilint_path else "tool-unavailable-on-host",
        },
        "baseline_runtime": baseline_runtime,
        "openssl_path": openssl_path,
        "pkilint_path": pkilint_path,
    }


def build_cross_tool_report(
    root: Path,
    *,
    registry_path: Path,
    java_path: Path | None,
    jar_path: Path | None,
    executable_path: Path | None,
) -> Dict[str, Any]:
    artifacts = gather_cross_tool_artifacts(root)
    requirement_map = requirement_index(registry_path)
    host = derive_tool_status(
        root,
        java_path=java_path,
        jar_path=jar_path,
        executable_path=executable_path,
    )
    rows: List[Dict[str, Any]] = []
    for record in artifacts:
        rows.append(run_extended_local_behavior(record, root, requirement_map))
        rows.append(
            run_jzlint_behavior(
                record,
                root,
                requirement_map,
                baseline_runtime=host["baseline_runtime"],
            )
        )
        rows.append(run_openssl_behavior(record, root, host["openssl_path"]))
        rows.append(run_pkilint_behavior(record, root, host["pkilint_path"]))

    summary = summarize_cross_tool_rows(rows)
    return {
        "profile": "pkix-core",
        "artifact_scope": {
            "artifact_count": len(artifacts),
            "certificate_count": sum(1 for record in artifacts if record.get("artifact_type") == "certificate"),
            "private_key_count": sum(
                1 for record in artifacts if record.get("artifact_type") == "private-key-container"
            ),
            "source_sets": dict(Counter(str(record.get("source_set")) for record in artifacts)),
        },
        "tool_status": host["tool_status"],
        "rows": rows,
        "summary": summary,
        "notes": [
            "This matrix is behavioral: acceptance and rejection reflect tool behavior, not proof of conformance.",
            "OpenSSL rows are parse/import signals only and should not be read as policy validation.",
            "JZLint baseline remains certificate-only and is marked not-applicable for private-key-container artifacts.",
            "Host unavailability is tracked separately from runtime fragility so the report does not over-claim semantic weakness.",
        ],
    }


def summarize_cross_tool_rows(rows: Iterable[Mapping[str, Any]]) -> Dict[str, Any]:
    rows = list(rows)
    by_tool_behavior: Dict[str, Dict[str, int]] = {}
    for tool in TOOL_ROWS:
        by_tool_behavior[tool] = dict(
            Counter(str(row.get("behavior")) for row in rows if row.get("tool") == tool)
        )
    openssl_divergence = sorted(
        row["artifact_id"]
        for row in rows
        if row.get("tool") == "openssl-cli" and row.get("behavior") == "accepted"
        and _paired_behavior(rows, row["artifact_id"], "extended-local") in {"rejected-structural", "rejected-semantic"}
    )
    baseline_fragility = sorted(
        row["artifact_id"]
        for row in rows
        if row.get("tool") == "jzlint-baseline"
        and row.get("behavior") == "runtime-failure"
        and row.get("validity") == "valid"
    )
    baseline_unavailable = sorted(
        row["artifact_id"]
        for row in rows
        if row.get("tool") == "jzlint-baseline"
        and row.get("behavior") == "tool-unavailable-on-host"
        and row.get("artifact_type") == "certificate"
    )
    importer_gap = sorted(
        row["artifact_id"]
        for row in rows
        if row.get("artifact_type") == "private-key-container"
        and row.get("tool") == "openssl-cli"
        and row.get("behavior") == "accepted"
        and _paired_behavior(rows, row["artifact_id"], "extended-local") == "rejected-semantic"
    )
    patterns = []
    if openssl_divergence:
        patterns.append(
            "OpenSSL parse acceptance diverges from local policy conformance on controlled invalid artifacts."
        )
    if baseline_fragility:
        patterns.append(
            "The frozen JZLint baseline still exhibits runtime fragility on valid PQ certificates."
        )
    if baseline_unavailable:
        patterns.append(
            "Some baseline rows reflect host unavailability rather than baseline semantics or runtime fragility."
        )
    if importer_gap:
        patterns.append(
            "Importer behavior remains under-specified across tools: OpenSSL accepts some containers the local policy gate rejects."
        )
    if not patterns:
        patterns.append("Cross-tool evidence remained mostly noisy or redundant with the existing baseline comparison.")
    return {
        "by_tool_behavior": by_tool_behavior,
        "openssl_parse_acceptance_vs_local_rejection": openssl_divergence,
        "baseline_runtime_fragility_on_valid_certificates": baseline_fragility,
        "baseline_host_unavailable_certificates": baseline_unavailable,
        "openssl_private_key_acceptance_vs_local_semantic_rejection": importer_gap,
        "patterns": patterns,
    }


def _paired_behavior(rows: Iterable[Mapping[str, Any]], artifact_id: str, tool: str) -> str | None:
    for row in rows:
        if row.get("artifact_id") == artifact_id and row.get("tool") == tool:
            return str(row.get("behavior"))
    return None


def _base_behavior_row(
    record: Mapping[str, Any],
    tool: str,
    behavior: str,
    signal_level: str,
    *,
    message: str = "",
    requirement_ids: Sequence[str] | None = None,
) -> Dict[str, Any]:
    if behavior not in BEHAVIOR_VALUES:
        raise ValueError(f"unsupported behavior value {behavior}")
    return {
        "artifact_id": record.get("artifact_id"),
        "artifact_type": record.get("artifact_type"),
        "algorithm": record.get("algorithm"),
        "parameter_set": record.get("parameter_set"),
        "stage": record.get("stage"),
        "validity": record.get("validity"),
        "source_set": record.get("source_set"),
        "path": record.get("path"),
        "tool": tool,
        "signal_level": signal_level,
        "behavior": behavior,
        "requirement_ids": list(requirement_ids or []),
        "message": message,
    }


def render_cross_tool_markdown(report: Mapping[str, Any]) -> str:
    lines = [
        "# Cross-Tool Behavior",
        "",
        "This document records tool behavior only. It does not treat parse acceptance as proof of conformance.",
        "",
        "## Tool Status",
        "",
    ]
    for tool, status in report["tool_status"].items():
        lines.append(f"- `{tool}`: `{status}`")
    lines.extend(["", "## Scope", ""])
    for key, value in report["artifact_scope"].items():
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## Patterns", ""])
    for pattern in report["summary"]["patterns"]:
        lines.append(f"- {pattern}")
    lines.extend(["", "## Behavior Counts", ""])
    for tool, counts in report["summary"]["by_tool_behavior"].items():
        lines.append(f"### {tool}")
        lines.append("")
        for behavior, count in sorted(counts.items()):
            lines.append(f"- `{behavior}`: {count}")
        lines.append("")
    lines.extend(["## Notes", ""])
    for note in report["notes"]:
        lines.append(f"- {note}")
    lines.append("")
    return "\n".join(lines)


def write_cross_tool_outputs(report: Mapping[str, Any], root: Path) -> Dict[str, Path]:
    results_dir = root / "results"
    docs_dir = root / "docs"
    results_dir.mkdir(parents=True, exist_ok=True)
    docs_dir.mkdir(parents=True, exist_ok=True)

    json_path = results_dir / "cross_tool_behavior_matrix.json"
    csv_path = results_dir / "cross_tool_behavior_matrix.csv"
    md_path = docs_dir / "cross-tool-behavior.md"

    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "artifact_id",
                "artifact_type",
                "algorithm",
                "parameter_set",
                "stage",
                "validity",
                "source_set",
                "path",
                "tool",
                "signal_level",
                "behavior",
                "finding_count",
                "requirement_ids",
                "message",
            ],
        )
        writer.writeheader()
        for row in report["rows"]:
            writer.writerow(
                {
                    **row,
                    "requirement_ids": " | ".join(str(item) for item in row.get("requirement_ids", [])),
                }
            )
    md_path.write_text(render_cross_tool_markdown(report), encoding="utf-8")
    return {
        "json": json_path,
        "csv": csv_path,
        "md": md_path,
    }


def main(argv: List[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", type=Path, default=root / "requirements.json")
    parser.add_argument(
        "--java",
        type=Path,
        default=None,
    )
    parser.add_argument(
        "--jzlint-jar",
        type=Path,
        default=root
        / "third_party"
        / "jzlint-main"
        / "jzlint-cli"
        / "target"
        / "jzlint-cli-2.0.1.jar",
    )
    parser.add_argument(
        "--baseline-executable",
        type=Path,
        default=root
        / "third_party"
        / "jzlint-main"
        / "jlint-pqc"
        / "src"
        / "main"
        / "resources"
        / "cli.exe",
    )
    args = parser.parse_args(argv)

    report = build_cross_tool_report(
        root,
        registry_path=args.registry,
        java_path=args.java,
        jar_path=args.jzlint_jar,
        executable_path=args.baseline_executable,
    )
    outputs = write_cross_tool_outputs(report, root)
    for path in outputs.values():
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
