"""Run local extended-suite bookkeeping."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List

from .extended_lints import detector_status
from .paths import project_relpath
from .policy import (
    VALID_MODES,
    VALID_PROFILES,
    artifact_policy_context,
    evaluate_policy,
    policy_matrix_rows,
    policy_summary,
    stage_owner_summary,
)
from .private_keys import lint_private_key_container_der
from .requirements import load_registry, registry_summary, requirements
from .x509 import DERError, lint_certificate_der, lint_spki_der, load_der


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    records: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                records.append(json.loads(stripped))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSONL: {exc}") from exc
    return records


def count(records: Iterable[Dict[str, Any]], key: str) -> Dict[str, int]:
    return dict(Counter(str(record.get(key, "unknown")) for record in records))


def summarize_findings(findings: List[Dict[str, str]], expected: Iterable[str]) -> Dict[str, Any]:
    expected_set = {str(item) for item in expected}
    error_findings = [
        finding for finding in findings if finding.get("status") == "error"
    ]
    ordered_error_requirements = [
        str(finding["requirement_id"]) for finding in error_findings
    ]
    error_instances = Counter(ordered_error_requirements)
    detected = set(error_instances)
    first_expected = next(
        (requirement for requirement in ordered_error_requirements if requirement in expected_set),
        None,
    )
    return {
        "detected_requirements": sorted(detected),
        "expected_detection_met": expected_set <= detected if expected_set else None,
        "missing_expected_requirements": sorted(expected_set - detected),
        "unexpected_error_requirements": sorted(detected - expected_set),
        "error_count": len(error_findings),
        "unique_error_count": len(detected),
        "redundant_error_count": len(error_findings) - len(detected),
        "error_instances_by_requirement": dict(sorted(error_instances.items())),
        "first_error_requirement": (
            ordered_error_requirements[0] if ordered_error_requirements else None
        ),
        "first_expected_requirement": first_expected,
    }


def write_registry_csv(path: Path, records: Iterable[Dict[str, Any]]) -> None:
    fields = [
        "id",
        "algorithm",
        "artifact_type",
        "stage",
        "profile",
        "owner",
        "detector_kind",
        "normative_strength",
        "constructibility",
        "fault_family",
        "source",
        "source_locators",
        "severity",
        "baseline_status",
        "mutation_family",
        "expected_detector",
        "mode_action",
        "justification",
        "detector_status",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for record in records:
            row = {field: csv_value(record.get(field, "")) for field in fields}
            row["detector_status"] = detector_status(str(record.get("expected_detector", "")))
            writer.writerow(row)


def csv_value(value: Any) -> str:
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True)
    if isinstance(value, list):
        return " | ".join(str(item) for item in value)
    return str(value)


def write_policy_matrix_csv(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    fields = [
        "id",
        "algorithm",
        "artifact_type",
        "stage",
        "profile",
        "owner",
        "detector_kind",
        "normative_strength",
        "constructibility",
        "baseline_status",
        "expected_detector",
        "deployable_action",
        "strict_action",
        "justification",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: csv_value(row.get(field, "")) for field in fields})
def build_report(
    registry_path: Path,
    manifest_path: Path,
    *,
    mode: str,
    profile: str,
) -> Dict[str, Any]:
    registry = load_registry(registry_path)
    reqs = requirements(registry)
    corpus_records = read_jsonl(manifest_path)
    detector_status_counts = Counter(
        detector_status(str(record.get("expected_detector", ""))) for record in reqs
    )
    return {
        "registry_path": project_relpath(registry_path),
        "manifest_path": project_relpath(manifest_path),
        "mode": mode,
        "profile": profile,
        "registry": registry_summary(registry),
        "detector_status": dict(detector_status_counts),
        "corpus": {
            "record_count": len(corpus_records),
            "by_validity": count(corpus_records, "validity"),
            "by_algorithm": count(corpus_records, "algorithm"),
            "by_fault_family": count(corpus_records, "fault_family"),
            "by_stage": count(corpus_records, "stage"),
        },
        "policy_summary": policy_summary(reqs, profile=profile, mode=mode),
        "stage_owner_summary": stage_owner_summary(reqs, profile=profile),
    }


def resolve_manifest_root(manifest_path: Path, records: List[Dict[str, Any]]) -> Path:
    rel_paths = [
        Path(str(record.get("path", "")))
        for record in records
        if record.get("path")
    ]
    if any(path.is_absolute() for path in rel_paths):
        return Path("/")
    samples = rel_paths[:5]
    manifest_resolved = manifest_path.resolve()
    candidates = [manifest_resolved.parent, *manifest_resolved.parents]
    for candidate in candidates:
        if all((candidate / path).exists() for path in samples):
            return candidate
    if "corpus" in manifest_resolved.parts:
        corpus_index = manifest_resolved.parts.index("corpus")
        return Path(*manifest_resolved.parts[:corpus_index])
    return manifest_resolved.parents[1]


def run_corpus(
    manifest_path: Path,
    registry_records: List[Dict[str, Any]],
    *,
    mode: str,
    profile: str,
) -> List[Dict[str, Any]]:
    records = read_jsonl(manifest_path)
    results: List[Dict[str, Any]] = []
    root = resolve_manifest_root(manifest_path, records)
    for record in records:
        artifact_type = record.get("artifact_type")
        expected = set(record.get("expected_detection", []))
        validity = str(record.get("validity", "unknown"))
        artifact_path = Path(str(record.get("path", "")))
        policy_context = artifact_policy_context(record, registry_records, profile=profile)
        if not artifact_path.is_absolute():
            artifact_path = root / artifact_path
        if artifact_type not in {"certificate", "spki", "private-key-container"}:
            summary = summarize_findings([], expected)
            results.append(
                {
                    "artifact_id": record.get("artifact_id"),
                    "artifact_type": artifact_type,
                    "algorithm": record.get("algorithm"),
                    "stage": record.get("stage"),
                    "parameter_set": record.get("parameter_set"),
                    "validity": validity,
                    "mode": mode,
                    "profile": profile,
                    **policy_context,
                    "status": "skipped",
                    "final_disposition": "skipped",
                    "message": "no detector implemented for this artifact_type yet",
                    "expected_detection": sorted(expected),
                    "findings": [],
                    "blocking_findings": [],
                    "warning_findings": [],
                    "ignored_findings": [],
                    "blocking_requirement_ids": [],
                    "warning_requirement_ids": [],
                    "ignored_requirement_ids": [],
                    "first_blocking_requirement": None,
                    "first_warning_requirement": None,
                    "blocking_count": 0,
                    "warning_count": 0,
                    "ignored_count": 0,
                    **summary,
                }
            )
            continue
        try:
            if artifact_type == "certificate":
                findings = lint_certificate_der(load_der(artifact_path))
            elif artifact_type == "private-key-container":
                findings = lint_private_key_container_der(load_der(artifact_path))
            else:
                findings = lint_spki_der(load_der(artifact_path))
            summary = summarize_findings(findings, expected)
            policy = evaluate_policy(
                findings,
                record,
                registry_records,
                mode=mode,
                profile=profile,
            )
            results.append(
                {
                    "artifact_id": record.get("artifact_id"),
                    "artifact_type": artifact_type,
                    "algorithm": record.get("algorithm"),
                    "stage": record.get("stage"),
                    "parameter_set": record.get("parameter_set"),
                    "validity": validity,
                    "path": project_relpath(artifact_path, root),
                    "status": policy["final_disposition"],
                    "expected_detection": sorted(expected),
                    "findings": findings,
                    **policy,
                    **summary,
                }
            )
        except (OSError, DERError, ValueError) as exc:
            summary = summarize_findings([], expected)
            results.append(
                {
                    "artifact_id": record.get("artifact_id"),
                    "artifact_type": artifact_type,
                    "algorithm": record.get("algorithm"),
                    "stage": record.get("stage"),
                    "parameter_set": record.get("parameter_set"),
                    "validity": validity,
                    "path": project_relpath(artifact_path, root),
                    "mode": mode,
                    "profile": profile,
                    **policy_context,
                    "status": "fatal",
                    "final_disposition": "fatal",
                    "message": str(exc),
                    "expected_detection": sorted(expected),
                    "findings": [],
                    "blocking_findings": [],
                    "warning_findings": [],
                    "ignored_findings": [],
                    "blocking_requirement_ids": [],
                    "warning_requirement_ids": [],
                    "ignored_requirement_ids": [],
                    "first_blocking_requirement": None,
                    "first_warning_requirement": None,
                    "blocking_count": 0,
                    "warning_count": 0,
                    "ignored_count": 0,
                    **summary,
                }
            )
    return results


def evaluation_summary(corpus_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    valid = [result for result in corpus_results if result.get("validity") == "valid"]
    invalid = [result for result in corpus_results if result.get("validity") == "invalid"]
    false_positive = [
        result
        for result in valid
        if result.get("final_disposition") in {"block", "warn"}
    ]
    blocking_valid = [
        result for result in valid if result.get("final_disposition") == "block"
    ]
    warning_valid = [
        result for result in valid if result.get("final_disposition") == "warn"
    ]
    expected_met = [
        result
        for result in invalid
        if result.get("expected_detection_met") is True
    ]
    expected_missed = [
        result
        for result in invalid
        if result.get("expected_detection_met") is False
    ]
    unexpected_errors = [
        result
        for result in corpus_results
        if result.get("unexpected_error_requirements")
    ]
    redundant_errors = [
        result
        for result in corpus_results
        if int(result.get("redundant_error_count", 0)) > 0
    ]
    return {
        "valid_count": len(valid),
        "invalid_count": len(invalid),
        "blocking_artifact_count": sum(
            1 for result in corpus_results if result.get("final_disposition") == "block"
        ),
        "warning_artifact_count": sum(
            1 for result in corpus_results if result.get("final_disposition") == "warn"
        ),
        "false_positive_count": len(false_positive),
        "false_positive_artifacts": [result.get("artifact_id") for result in false_positive],
        "blocking_valid_artifact_count": len(blocking_valid),
        "blocking_valid_artifacts": [result.get("artifact_id") for result in blocking_valid],
        "warning_valid_artifact_count": len(warning_valid),
        "warning_valid_artifacts": [result.get("artifact_id") for result in warning_valid],
        "invalid_expected_detection_met": len(expected_met),
        "invalid_expected_detection_missed": len(expected_missed),
        "invalid_expected_detection_missed_artifacts": [
            result.get("artifact_id") for result in expected_missed
        ],
        "unexpected_error_artifact_count": len(unexpected_errors),
        "unexpected_error_artifacts": [
            result.get("artifact_id") for result in unexpected_errors
        ],
        "redundant_error_artifact_count": len(redundant_errors),
        "redundant_error_artifacts": [
            result.get("artifact_id") for result in redundant_errors
        ],
    }


def output_path(out_dir: Path, base_name: str, mode: str, suffix: str) -> Path:
    if mode == "strict":
        return out_dir / f"{base_name}{suffix}"
    return out_dir / f"{base_name}_{mode}{suffix}"


def maybe_write_strict_alias(path: Path, alias_name: str, mode: str, content: str) -> None:
    if mode != "strict":
        return
    alias_path = path.parent / alias_name
    alias_path.write_text(content, encoding="utf-8")


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--registry",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "requirements.json",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "corpus" / "manifest.jsonl",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "results",
    )
    parser.add_argument("--mode", choices=list(VALID_MODES), default="strict")
    parser.add_argument("--profile", choices=list(VALID_PROFILES), default="pkix-core")
    args = parser.parse_args(argv)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    registry = load_registry(args.registry)
    registry_records = requirements(registry)
    report = build_report(
        args.registry,
        args.manifest,
        mode=args.mode,
        profile=args.profile,
    )
    corpus_results = run_corpus(
        args.manifest,
        registry_records,
        mode=args.mode,
        profile=args.profile,
    )
    report["extended_lint_results"] = {
        "artifact_count": len(corpus_results),
        "by_status": count(corpus_results, "status"),
        "evaluation": evaluation_summary(corpus_results),
    }

    summary_content = json.dumps(report, indent=2, sort_keys=True) + "\n"
    summary_path = output_path(args.out_dir, "extended_registry_summary", args.mode, ".json")
    summary_path.write_text(summary_content, encoding="utf-8")

    csv_path = output_path(args.out_dir, "extended_registry_requirements", args.mode, ".csv")
    write_registry_csv(csv_path, registry_records)

    lint_results_path = output_path(args.out_dir, "extended_lint_results", args.mode, ".jsonl")
    with lint_results_path.open("w", encoding="utf-8") as handle:
        for result in corpus_results:
            handle.write(json.dumps(result, sort_keys=True) + "\n")

    policy_summary_path = args.out_dir / f"policy_summary_{args.mode}.json"
    policy_summary_path.write_text(
        json.dumps(policy_summary(registry_records, profile=args.profile, mode=args.mode), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    policy_matrix_path = args.out_dir / "policy_matrix.csv"
    write_policy_matrix_csv(policy_matrix_path, policy_matrix_rows(registry_records))
    stage_owner_summary_path = args.out_dir / "stage_owner_summary.json"
    stage_owner_summary_path.write_text(
        json.dumps(stage_owner_summary(registry_records, profile=args.profile), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    maybe_write_strict_alias(summary_path, "extended_registry_summary.json", args.mode, summary_content)
    if args.mode == "strict":
        write_registry_csv(args.out_dir / "extended_registry_requirements.csv", registry_records)
        with (args.out_dir / "extended_lint_results.jsonl").open("w", encoding="utf-8") as handle:
            for result in corpus_results:
                handle.write(json.dumps(result, sort_keys=True) + "\n")

    print(f"wrote {summary_path}")
    print(f"wrote {csv_path}")
    print(f"wrote {lint_results_path}")
    print(f"wrote {policy_summary_path}")
    print(f"wrote {policy_matrix_path}")
    print(f"wrote {stage_owner_summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
