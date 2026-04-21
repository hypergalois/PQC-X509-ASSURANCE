"""Coverage summaries for policy-aware PQ X.509 assurance."""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set

from .extended_lints import detector_status
from .paths import project_relpath
from .policy import (
    VALID_MODES,
    VALID_PROFILES,
    applicable_requirements,
    requirement_action,
)
from .requirements import load_registry, requirements
from .run_extended import read_jsonl


DEFAULT_TARGET_STAGES = ("certificate/profile", "SPKI/public-key")


def as_set(value: Any) -> Set[str]:
    if value is None:
        return set()
    if isinstance(value, list):
        return {str(item) for item in value}
    return {str(value)}
def build_coverage(
    registry_path: Path,
    manifest_path: Path,
    results_path: Path,
    target_stages: Iterable[str] | None = None,
    *,
    mode: str,
    profile: str,
) -> Dict[str, Any]:
    target_stage_set = set(target_stages or DEFAULT_TARGET_STAGES)
    reqs = [
        req
        for req in applicable_requirements(
            requirements(load_registry(registry_path)),
            profile=profile,
        )
        if req.get("stage") in target_stage_set
    ]
    req_index = {str(req["id"]): req for req in reqs}
    manifest = read_jsonl(manifest_path)
    results = read_jsonl(results_path)

    expected_by_req: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    mutation_families_by_req: Dict[str, Set[str]] = defaultdict(set)
    for record in manifest:
        for req_id in record.get("expected_detection", []):
            expected_by_req[str(req_id)].append(record)
            mutation_families_by_req[str(req_id)].update(as_set(record.get("mutation_family")))

    valid_pass_by_req: Dict[str, Set[str]] = defaultdict(set)
    for result in results:
        if result.get("validity") != "valid":
            continue
        applicable_ids = {
            str(item) for item in result.get("applicable_requirement_ids", [])
        }
        for finding in result.get("findings", []):
            requirement_id = str(finding.get("requirement_id"))
            if finding.get("status") != "pass":
                continue
            if requirement_id not in applicable_ids:
                continue
            if requirement_id not in req_index:
                continue
            valid_pass_by_req[requirement_id].add(str(result.get("artifact_id")))

    rows = []
    for req in reqs:
        req_id = str(req["id"])
        expected_records = expected_by_req.get(req_id, [])
        expected_families = set(str(item) for item in req.get("mutation_family", []))
        observed_families = mutation_families_by_req.get(req_id, set())
        action = requirement_action(req, mode)
        status = classify_requirement(
            detector_status(str(req.get("expected_detector", ""))),
            len(valid_pass_by_req.get(req_id, set())),
            len(expected_records),
            action,
        )
        rows.append(
            {
                "requirement_id": req_id,
                "algorithm": req.get("algorithm"),
                "stage": req.get("stage"),
                "artifact_type": req.get("artifact_type"),
                "profile": req.get("profile"),
                "owner": req.get("owner"),
                "detector_kind": req.get("detector_kind"),
                "normative_strength": req.get("normative_strength"),
                "constructibility": req.get("constructibility"),
                "fault_family": req.get("fault_family"),
                "detector": req.get("expected_detector"),
                "detector_status": detector_status(str(req.get("expected_detector", ""))),
                "mode": mode,
                "active_action": action,
                "deployable_action": requirement_action(req, "deployable"),
                "strict_action": requirement_action(req, "strict"),
                "valid_pass_artifact_count": len(valid_pass_by_req.get(req_id, set())),
                "negative_artifact_count": len(expected_records),
                "negative_artifacts": sorted(str(record["artifact_id"]) for record in expected_records),
                "registry_mutation_families": sorted(expected_families),
                "observed_mutation_families": sorted(observed_families),
                "uncovered_mutation_families": sorted(expected_families - observed_families),
                "coverage_status": status,
            }
        )

    mutation_rows = mutation_detection_rows(results, target_stage_set)
    project_root = Path(__file__).resolve().parents[2]
    return {
        "registry_path": project_relpath(registry_path, project_root),
        "manifest_path": project_relpath(manifest_path, project_root),
        "results_path": project_relpath(results_path, project_root),
        "profile": profile,
        "mode": mode,
        "target_stages": sorted(target_stage_set),
        "requirement_count": len(rows),
        "by_coverage_status": count_by(rows, "coverage_status"),
        "requirements": rows,
        "open_detector_gaps": [
            row for row in rows if not row["coverage_status"].startswith("covered-")
        ],
        "mutation_detection_summary": mutation_detection_summary(mutation_rows),
        "mutation_detection": mutation_rows,
    }


def classify_requirement(
    detector_state: str,
    valid_count: int,
    negative_count: int,
    action: str,
) -> str:
    if detector_state != "implemented":
        return detector_state
    if valid_count > 0 and negative_count > 0:
        return f"covered-{action}"
    if valid_count == 0:
        return "needs-valid-artifact"
    return "needs-negative-artifact"


def count_by(rows: Iterable[Dict[str, Any]], field: str) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for row in rows:
        key = str(row.get(field, "unknown"))
        counts[key] = counts.get(key, 0) + 1
    return counts


def mutation_detection_rows(
    results: List[Dict[str, Any]],
    target_stages: Set[str],
) -> List[Dict[str, Any]]:
    rows = []
    for result in results:
        if result.get("validity") != "invalid":
            continue
        if str(result.get("stage")) not in target_stages:
            continue
        rows.append(
            {
                "artifact_id": result.get("artifact_id"),
                "algorithm": result.get("algorithm"),
                "stage": result.get("stage"),
                "status": result.get("status"),
                "final_disposition": result.get("final_disposition"),
                "expected_detection": result.get("expected_detection", []),
                "detected_requirements": result.get("detected_requirements", []),
                "blocking_requirement_ids": result.get("blocking_requirement_ids", []),
                "warning_requirement_ids": result.get("warning_requirement_ids", []),
                "ignored_requirement_ids": result.get("ignored_requirement_ids", []),
                "expected_detection_met": result.get("expected_detection_met"),
                "first_blocking_requirement": result.get("first_blocking_requirement"),
                "first_warning_requirement": result.get("first_warning_requirement"),
                "first_expected_requirement": result.get("first_expected_requirement"),
                "error_count": result.get("error_count", 0),
                "unique_error_count": result.get("unique_error_count", 0),
                "redundant_error_count": result.get("redundant_error_count", 0),
                "missing_expected_requirements": result.get("missing_expected_requirements", []),
                "unexpected_error_requirements": result.get("unexpected_error_requirements", []),
            }
        )
    return rows


def mutation_detection_summary(rows: List[Dict[str, Any]]) -> Dict[str, int]:
    return {
        "invalid_artifact_count": len(rows),
        "expected_detection_met_count": sum(
            1 for row in rows if row.get("expected_detection_met") is True
        ),
        "expected_detection_missed_count": sum(
            1 for row in rows if row.get("expected_detection_met") is False
        ),
        "unexpected_error_artifact_count": sum(
            1 for row in rows if row.get("unexpected_error_requirements")
        ),
        "redundant_error_artifact_count": sum(
            1 for row in rows if int(row.get("redundant_error_count", 0)) > 0
        ),
        "by_final_disposition": count_by(rows, "final_disposition"),
    }


def csv_value(value: Any) -> str:
    if isinstance(value, list):
        return " | ".join(str(item) for item in value)
    return str(value)


def write_csv(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    fields = [
        "requirement_id",
        "algorithm",
        "stage",
        "artifact_type",
        "profile",
        "owner",
        "detector_kind",
        "normative_strength",
        "constructibility",
        "fault_family",
        "detector",
        "detector_status",
        "mode",
        "active_action",
        "deployable_action",
        "strict_action",
        "valid_pass_artifact_count",
        "negative_artifact_count",
        "negative_artifacts",
        "registry_mutation_families",
        "observed_mutation_families",
        "uncovered_mutation_families",
        "coverage_status",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: csv_value(row.get(field, "")) for field in fields})


def main(argv: List[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", type=Path, default=root / "requirements.json")
    parser.add_argument("--manifest", type=Path, default=root / "corpus" / "manifest.jsonl")
    parser.add_argument(
        "--results",
        type=Path,
        default=None,
    )
    parser.add_argument("--out-dir", type=Path, default=root / "results")
    parser.add_argument("--stages", nargs="+", default=list(DEFAULT_TARGET_STAGES))
    parser.add_argument("--stem", default="certificate_spki_coverage")
    parser.add_argument("--mode", choices=list(VALID_MODES), default="strict")
    parser.add_argument("--profile", choices=list(VALID_PROFILES), default="pkix-core")
    args = parser.parse_args(argv)
    if args.results is None:
        results_name = "extended_lint_results.jsonl"
        if args.mode != "strict":
            results_name = f"extended_lint_results_{args.mode}.jsonl"
        args.results = root / "results" / results_name

    args.out_dir.mkdir(parents=True, exist_ok=True)
    report = build_coverage(
        args.registry,
        args.manifest,
        args.results,
        args.stages,
        mode=args.mode,
        profile=args.profile,
    )
    suffix = "" if args.mode == "strict" else f"_{args.mode}"
    json_path = args.out_dir / f"{args.stem}{suffix}.json"
    csv_path = args.out_dir / f"{args.stem}{suffix}.csv"
    content = json.dumps(report, indent=2, sort_keys=True) + "\n"
    json_path.write_text(content, encoding="utf-8")
    write_csv(csv_path, report["requirements"])
    if args.mode == "strict":
        (args.out_dir / f"{args.stem}.json").write_text(content, encoding="utf-8")
        write_csv(args.out_dir / f"{args.stem}.csv", report["requirements"])
    print(f"wrote {json_path}")
    print(f"wrote {csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
