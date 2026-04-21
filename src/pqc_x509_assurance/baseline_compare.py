"""
Compare host-real JZLint baseline results against the extended suite.

The frozen JZLint baseline consumes certificates, not raw SPKI blobs or private-key containers, and some ML-KEM checks rely on an external executable path that is not portable in the archived snapshot.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
import subprocess
import tempfile
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping

from .host_tools import baseline_host_status, build_jzlint_cli
from .paths import project_relpath, project_root
from .requirements import load_registry, requirements
from .run_extended import read_jsonl, resolve_manifest_root, summarize_findings
from .x509 import DERError, lint_certificate_der, load_der


BASELINE_LINT_TO_REQUIREMENT: Dict[str, str] = {
    "e_ml_kem_key_usage": "MLKEM-CERT-KU-KEYENCIPHERMENT-ONLY",
    "e_ml_kem_public_key_aid_encoding": "MLKEM-SPKI-AID-PARAMS-ABSENT",
    "e_ml_kem_ek_length": "MLKEM-SPKI-PUBLIC-KEY-LENGTH",
    "e_ml_kem_ek_encoding": "MLKEM-SPKI-ENCODE-DECODE-IDENTITY",
    "e_ml_dsa_key_usage": "MLDSA-CERT-KU-NO-ENCIPHERMENT-OR-AGREEMENT",
    "e_ml_dsa_public_key_aid_encoding": "MLDSA-SPKI-AID-PARAMS-ABSENT",
    "e_ml_dsa_signature_aid_encoding": "MLDSA-CERT-SIGNATURE-AID-PARAMS-ABSENT",
}


def certificate_records(manifest_path: Path) -> List[Dict[str, Any]]:
    return [
        record
        for record in read_jsonl(manifest_path)
        if record.get("artifact_type") == "certificate"
    ]


def percentile(values: List[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(q * len(ordered)) - 1))
    return ordered[index]


def latency_summary(values: List[float]) -> Dict[str, float | None]:
    if not values:
        return {"mean": None, "median": None, "p95": None, "max": None}
    return {
        "mean": round(statistics.fmean(values), 3),
        "median": round(statistics.median(values), 3),
        "p95": round(percentile(values, 0.95) or 0.0, 3),
        "max": round(max(values), 3),
    }


def _properties_text(tmp_dir: Path, executable_path: Path) -> str:
    return (
        f"tmp.dir={tmp_dir}\n"
        f"executable.path={executable_path}\n"
        "delete.files=true\n"
    )


def run_baseline_cli(
    *,
    java_path: Path,
    jar_path: Path,
    executable_path: Path,
    certificate_path: Path,
) -> Dict[str, Any]:
    certificate_label = certificate_path.name
    with tempfile.TemporaryDirectory(prefix="pqc-baseline-") as tmp_name:
        tmp_dir = Path(tmp_name)
        (tmp_dir / "jzlint.properties").write_text(
            _properties_text(tmp_dir, executable_path),
            encoding="utf-8",
        )
        started = time.perf_counter()
        process = subprocess.run(
            [
                str(java_path),
                "-jar",
                str(jar_path),
                str(certificate_path),
                "-includeSources",
                "PQC",
            ],
            cwd=tmp_dir,
            text=True,
            capture_output=True,
            check=False,
        )
        elapsed_ms = (time.perf_counter() - started) * 1000.0
    stdout = process.stdout.strip()
    if process.returncode != 0:
        raise RuntimeError(
            f"baseline CLI returned {process.returncode} for {certificate_label}: {process.stderr.strip()}"
        )
    if not stdout:
        raise RuntimeError(f"baseline CLI produced no JSON output for {certificate_label}")
    try:
        raw_results = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"baseline CLI produced invalid JSON for {certificate_label}: {stdout[:200]}"
        ) from exc
    if not isinstance(raw_results, dict):
        raise RuntimeError(f"baseline CLI output is not a JSON object for {certificate_label}")
    return {
        "raw_lint_results": raw_results,
        "elapsed_ms": round(elapsed_ms, 3),
        "stderr": process.stderr.strip(),
    }


def normalize_baseline_result(
    record: Mapping[str, Any],
    raw_results: Mapping[str, Any],
    elapsed_ms: float,
    stderr: str,
) -> Dict[str, Any]:
    expected = set(record.get("expected_detection", []))
    findings: List[Dict[str, str]] = []
    raw_status_counts: Counter[str] = Counter()
    fatal_lints: List[str] = []
    fatal_requirements: List[str] = []
    for lint_name, payload in raw_results.items():
        if not isinstance(payload, dict):
            continue
        status = str(payload.get("result", "unknown")).lower()
        raw_status_counts[status] += 1
        requirement_id = BASELINE_LINT_TO_REQUIREMENT.get(lint_name)
        if requirement_id is None:
            continue
        if status == "error":
            findings.append(
                {
                    "requirement_id": requirement_id,
                    "detector": f"baseline.jzlint.{lint_name}",
                    "status": "error",
                    "message": f"Baseline lint {lint_name} returned error.",
                }
            )
        elif status == "fatal":
            fatal_lints.append(lint_name)
            fatal_requirements.append(requirement_id)
    summary = summarize_findings(findings, expected)
    status = "error" if summary["error_count"] else ("fatal" if fatal_lints else "pass")
    fatal_requirement_set = set(fatal_requirements)
    return {
        "artifact_id": record.get("artifact_id"),
        "artifact_type": record.get("artifact_type"),
        "algorithm": record.get("algorithm"),
        "stage": record.get("stage"),
        "parameter_set": record.get("parameter_set"),
        "validity": record.get("validity"),
        "path": record.get("path"),
        "status": status,
        "elapsed_ms": elapsed_ms,
        "expected_detection": sorted(expected),
        "findings": findings,
        "raw_lint_results": raw_results,
        "raw_lint_status_counts": dict(sorted(raw_status_counts.items())),
        "fatal_lints": sorted(fatal_lints),
        "fatal_requirement_candidates": sorted(fatal_requirement_set),
        "expected_requirements_blocked_by_fatal": sorted(
            expected.intersection(fatal_requirement_set) - set(summary["detected_requirements"])
        ),
        "stderr": stderr,
        **summary,
    }


def run_extended_certificate(record: Mapping[str, Any], root: Path) -> Dict[str, Any]:
    expected = set(record.get("expected_detection", []))
    artifact_path = root / str(record.get("path"))
    try:
        started = time.perf_counter()
        findings = lint_certificate_der(load_der(artifact_path))
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        summary = summarize_findings(findings, expected)
        status = "error" if summary["error_count"] else "pass"
        return {
            "artifact_id": record.get("artifact_id"),
            "artifact_type": record.get("artifact_type"),
            "algorithm": record.get("algorithm"),
            "stage": record.get("stage"),
            "parameter_set": record.get("parameter_set"),
            "validity": record.get("validity"),
            "path": project_relpath(artifact_path, root),
            "status": status,
            "elapsed_ms": round(elapsed_ms, 3),
            "expected_detection": sorted(expected),
            "findings": findings,
            **summary,
        }
    except (OSError, DERError, ValueError) as exc:
        summary = summarize_findings([], expected)
        return {
            "artifact_id": record.get("artifact_id"),
            "artifact_type": record.get("artifact_type"),
            "algorithm": record.get("algorithm"),
            "stage": record.get("stage"),
            "parameter_set": record.get("parameter_set"),
            "validity": record.get("validity"),
            "path": project_relpath(artifact_path, root),
            "status": "fatal",
            "elapsed_ms": None,
            "expected_detection": sorted(expected),
            "findings": [],
            "message": str(exc),
            **summary,
        }


def evaluation_summary(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    valid = [result for result in results if result.get("validity") == "valid"]
    invalid = [result for result in results if result.get("validity") == "invalid"]
    false_positive = [result for result in valid if result.get("status") == "error"]
    fatal_artifacts = [result for result in results if result.get("fatal_lints") or result.get("status") == "fatal"]
    fatal_valid = [result for result in valid if result in fatal_artifacts]
    fatal_invalid = [result for result in invalid if result in fatal_artifacts]
    expected_met = [result for result in invalid if result.get("expected_detection_met") is True]
    expected_missed = [result for result in invalid if result.get("expected_detection_met") is False]
    useful_hit = [result for result in invalid if result.get("first_expected_requirement")]
    unexpected = [result for result in results if result.get("unexpected_error_requirements")]
    redundant = [result for result in results if int(result.get("redundant_error_count", 0)) > 0]
    elapsed = [
        float(result["elapsed_ms"])
        for result in results
        if result.get("elapsed_ms") is not None
    ]
    return {
        "artifact_count": len(results),
        "by_status": dict(Counter(str(result.get("status", "unknown")) for result in results)),
        "valid_count": len(valid),
        "invalid_count": len(invalid),
        "false_positive_count": len(false_positive),
        "false_positive_artifacts": [result.get("artifact_id") for result in false_positive],
        "artifacts_with_fatal_lints": len(fatal_artifacts),
        "fatal_valid_artifact_count": len(fatal_valid),
        "fatal_valid_artifacts": [result.get("artifact_id") for result in fatal_valid],
        "fatal_invalid_artifact_count": len(fatal_invalid),
        "fatal_invalid_artifacts": [result.get("artifact_id") for result in fatal_invalid],
        "invalid_expected_detection_met": len(expected_met),
        "invalid_expected_detection_missed": len(expected_missed),
        "invalid_expected_detection_missed_artifacts": [
            result.get("artifact_id") for result in expected_missed
        ],
        "first_useful_hit_count": len(useful_hit),
        "first_useful_hit_artifacts": [result.get("artifact_id") for result in useful_hit],
        "unexpected_error_artifact_count": len(unexpected),
        "unexpected_error_artifacts": [result.get("artifact_id") for result in unexpected],
        "redundant_error_artifact_count": len(redundant),
        "redundant_error_artifacts": [result.get("artifact_id") for result in redundant],
        "latency_ms": latency_summary(elapsed),
    }


def improvement_class(
    baseline: Mapping[str, Any],
    extended: Mapping[str, Any],
) -> str:
    baseline_met = baseline.get("expected_detection_met") is True
    extended_met = extended.get("expected_detection_met") is True
    baseline_fatal = bool(baseline.get("fatal_lints")) or baseline.get("status") == "fatal"
    if not baseline_met and extended_met:
        if baseline_fatal:
            return "extended-recovers-baseline-miss-and-runtime-fragility"
        return "extended-recovers-baseline-miss"
    if baseline_met and extended_met and baseline_fatal:
        return "extended-matches-detection-without-baseline-runtime-fragility"
    if baseline_met and extended_met:
        return "same-detection"
    if baseline.get("status") == "pass" and extended.get("status") == "pass":
        return "same-pass"
    if baseline_fatal and extended.get("status") != "fatal":
        return "baseline-runtime-fragile"
    return "same-gap"


def requirement_level_summary(
    cert_records: List[Dict[str, Any]],
    baseline_results: Mapping[str, Dict[str, Any]],
    extended_results: Mapping[str, Dict[str, Any]],
    registry_path: Path,
) -> List[Dict[str, Any]]:
    relevant_requirements = {
        req["id"]: req
        for req in requirements(load_registry(registry_path))
        if req.get("stage") in {"certificate/profile", "SPKI/public-key"}
    }
    expected_by_requirement: Dict[str, List[str]] = defaultdict(list)
    for record in cert_records:
        for requirement_id in record.get("expected_detection", []):
            expected_by_requirement[str(requirement_id)].append(str(record.get("artifact_id")))

    rows: List[Dict[str, Any]] = []
    for requirement_id, req in sorted(relevant_requirements.items()):
        expected_artifacts = sorted(expected_by_requirement.get(requirement_id, []))
        baseline_detected = []
        baseline_blocked_by_fatal = []
        extended_detected = []
        for artifact_id in expected_artifacts:
            baseline_result = baseline_results[artifact_id]
            extended_result = extended_results[artifact_id]
            if requirement_id in baseline_result.get("detected_requirements", []):
                baseline_detected.append(artifact_id)
            if requirement_id in baseline_result.get("expected_requirements_blocked_by_fatal", []):
                baseline_blocked_by_fatal.append(artifact_id)
            if requirement_id in extended_result.get("detected_requirements", []):
                extended_detected.append(artifact_id)
        rows.append(
            {
                "requirement_id": requirement_id,
                "algorithm": req.get("algorithm"),
                "stage": req.get("stage"),
                "baseline_status": req.get("baseline_status"),
                "expected_artifact_count": len(expected_artifacts),
                "expected_artifacts": expected_artifacts,
                "baseline_detected_count": len(baseline_detected),
                "baseline_detected_artifacts": baseline_detected,
                "baseline_blocked_by_fatal_count": len(baseline_blocked_by_fatal),
                "baseline_blocked_by_fatal_artifacts": baseline_blocked_by_fatal,
                "extended_detected_count": len(extended_detected),
                "extended_detected_artifacts": extended_detected,
            }
        )
    return rows


def comparison_rows(
    cert_records: List[Dict[str, Any]],
    baseline_results: Mapping[str, Dict[str, Any]],
    extended_results: Mapping[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for record in cert_records:
        artifact_id = str(record.get("artifact_id"))
        baseline = baseline_results[artifact_id]
        extended = extended_results[artifact_id]
        rows.append(
            {
                "artifact_id": artifact_id,
                "algorithm": record.get("algorithm"),
                "parameter_set": record.get("parameter_set"),
                "validity": record.get("validity"),
                "expected_detection": list(record.get("expected_detection", [])),
                "baseline_status": baseline.get("status"),
                "baseline_expected_detection_met": baseline.get("expected_detection_met"),
                "baseline_detected_requirements": baseline.get("detected_requirements", []),
                "baseline_fatal_lints": baseline.get("fatal_lints", []),
                "baseline_expected_blocked_by_fatal": baseline.get(
                    "expected_requirements_blocked_by_fatal", []
                ),
                "baseline_first_expected_requirement": baseline.get("first_expected_requirement"),
                "baseline_elapsed_ms": baseline.get("elapsed_ms"),
                "extended_status": extended.get("status"),
                "extended_expected_detection_met": extended.get("expected_detection_met"),
                "extended_detected_requirements": extended.get("detected_requirements", []),
                "extended_first_expected_requirement": extended.get("first_expected_requirement"),
                "extended_elapsed_ms": extended.get("elapsed_ms"),
                "comparison_class": improvement_class(baseline, extended),
            }
        )
    return rows


def write_jsonl(path: Path, records: Iterable[Mapping[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True))
            handle.write("\n")


def csv_value(value: Any) -> str:
    if isinstance(value, list):
        return " | ".join(str(item) for item in value)
    return str(value)


def write_csv(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    rows = list(rows)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: csv_value(value) for key, value in row.items()})


def ensure_baseline_runtime(
    root: Path,
    *,
    java_path: Path | None,
    jar_path: Path | None,
    executable_path: Path | None,
) -> Dict[str, Path]:
    status = baseline_host_status(
        root,
        explicit_java=java_path,
        explicit_jar=jar_path,
        explicit_executable=executable_path,
    )
    if status["available"]:
        return {
            "java_path": status["java_path"],
            "jar_path": status["jar_path"],
            "executable_path": status["executable_path"],
        }
    if status["build_possible"]:
        build = build_jzlint_cli(
            root,
            snapshot_path=status["snapshot_path"],
            maven_path=status["maven_path"],
        )
        if build["success"]:
            refreshed = baseline_host_status(
                root,
                explicit_java=status["java_path"],
                explicit_jar=Path(build["jar_path"]),
                explicit_executable=status["executable_path"],
            )
            if refreshed["available"]:
                return {
                    "java_path": refreshed["java_path"],
                    "jar_path": refreshed["jar_path"],
                    "executable_path": refreshed["executable_path"],
                }
            raise RuntimeError(
                f"host-unavailable: baseline CLI still unavailable after build: {refreshed['reason']}"
            )
        raise RuntimeError(f"host-unavailable: {build['message']}")
    raise RuntimeError(f"host-unavailable: {status['reason']}")


def main(argv: List[str] | None = None) -> int:
    root = project_root()
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=root / "corpus" / "manifest.jsonl")
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
    parser.add_argument("--out-dir", type=Path, default=root / "results")
    args = parser.parse_args(argv)
    try:
        runtime = ensure_baseline_runtime(
            root,
            java_path=args.java,
            jar_path=args.jzlint_jar,
            executable_path=args.baseline_executable,
        )
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc

    certs = certificate_records(args.manifest)
    baseline_results: List[Dict[str, Any]] = []
    extended_results: List[Dict[str, Any]] = []
    corpus_root = resolve_manifest_root(args.manifest, certs)
    for record in certs:
        artifact_path = corpus_root / str(record.get("path"))
        baseline_raw = run_baseline_cli(
            java_path=runtime["java_path"],
            jar_path=runtime["jar_path"],
            executable_path=runtime["executable_path"],
            certificate_path=artifact_path,
        )
        baseline_results.append(
            normalize_baseline_result(
                record,
                baseline_raw["raw_lint_results"],
                float(baseline_raw["elapsed_ms"]),
                str(baseline_raw["stderr"]),
            )
        )
        extended_results.append(run_extended_certificate(record, corpus_root))

    baseline_by_artifact = {
        str(result["artifact_id"]): result for result in baseline_results
    }
    extended_by_artifact = {
        str(result["artifact_id"]): result for result in extended_results
    }
    comparison = comparison_rows(certs, baseline_by_artifact, extended_by_artifact)
    requirement_summary = requirement_level_summary(
        certs,
        baseline_by_artifact,
        extended_by_artifact,
        args.registry,
    )

    report = {
        "scope": {
            "artifact_type": "certificate",
            "artifact_count": len(certs),
            "valid_count": sum(1 for record in certs if record.get("validity") == "valid"),
            "invalid_count": sum(1 for record in certs if record.get("validity") == "invalid"),
            "java_binary": runtime["java_path"].name,
            "baseline_snapshot": "third_party/jzlint-main",
            "baseline_executable": project_relpath(runtime["executable_path"], root),
            "note": (
                "Comparison is certificate-only. Raw SPKI and private-key-container "
                "artifacts remain outside the frozen JZLint CLI baseline."
            ),
        },
        "baseline": evaluation_summary(baseline_results),
        "extended": evaluation_summary(extended_results),
        "comparison": {
            "improvement_classes": dict(
                Counter(str(row["comparison_class"]) for row in comparison)
            ),
            "baseline_missed_extended_met_artifacts": [
                row["artifact_id"]
                for row in comparison
                if (
                    row["baseline_expected_detection_met"] is not True
                    and row["extended_expected_detection_met"] is True
                )
            ],
            "baseline_fatal_extended_clean_artifacts": [
                row["artifact_id"]
                for row in comparison
                if row["baseline_fatal_lints"] and row["extended_status"] != "fatal"
            ],
            "requirement_level": requirement_summary,
        },
    }

    args.out_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(args.out_dir / "baseline_jzlint_certificate_results.jsonl", baseline_results)
    write_jsonl(args.out_dir / "extended_certificate_eval.jsonl", extended_results)
    write_csv(
        args.out_dir / "baseline_vs_extended_certificate_comparison.csv",
        comparison,
    )
    with (args.out_dir / "baseline_vs_extended_certificate_report.json").open(
        "w", encoding="utf-8"
    ) as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
