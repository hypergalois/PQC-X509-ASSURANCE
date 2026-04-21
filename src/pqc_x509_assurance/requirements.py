"""Helpers for the normative assurance registry."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List

from .policy import validate_requirement_policy


Registry = Dict[str, Any]
Requirement = Dict[str, Any]

REQUIRED_REQUIREMENT_FIELDS = {
    "id",
    "algorithm",
    "artifact_type",
    "stage",
    "fault_family",
    "source",
    "source_locators",
    "requirement",
    "severity",
    "baseline_status",
    "mutation_family",
    "expected_detector",
    "owner",
    "detector_kind",
    "normative_strength",
    "mode_action",
    "justification",
    "constructibility",
    "profile",
    "gate_pack",
}


def load_registry(path: Path) -> Registry:
    with path.open("r", encoding="utf-8") as handle:
        registry = json.load(handle)
    if "requirements" not in registry or not isinstance(registry["requirements"], list):
        raise ValueError(f"{path} does not contain a requirements list")
    validate_registry(registry, path)
    return registry


def requirements(registry: Registry) -> List[Requirement]:
    return list(registry["requirements"])


def validate_registry(registry: Registry, path: Path) -> None:
    for index, record in enumerate(registry["requirements"], start=1):
        missing = sorted(field for field in REQUIRED_REQUIREMENT_FIELDS if field not in record)
        if missing:
            req_id = record.get("id", f"#{index}")
            raise ValueError(f"{path}: requirement {req_id} missing fields: {', '.join(missing)}")
        for list_field in ("source", "source_locators", "mutation_family"):
            if not isinstance(record[list_field], list) or not record[list_field]:
                raise ValueError(f"{path}: requirement {record['id']} field {list_field} must be a non-empty list")
        validate_requirement_policy(record, str(path))


def count_by(records: Iterable[Requirement], field: str) -> Dict[str, int]:
    return dict(Counter(str(record.get(field, "unknown")) for record in records))


def registry_summary(registry: Registry) -> Dict[str, Any]:
    records = requirements(registry)
    return {
        "schema_version": registry.get("schema_version"),
        "requirement_count": len(records),
        "by_algorithm": count_by(records, "algorithm"),
        "by_stage": count_by(records, "stage"),
        "by_fault_family": count_by(records, "fault_family"),
        "by_baseline_status": count_by(records, "baseline_status"),
        "by_severity": count_by(records, "severity"),
        "by_owner": count_by(records, "owner"),
        "by_detector_kind": count_by(records, "detector_kind"),
        "by_normative_strength": count_by(records, "normative_strength"),
        "by_constructibility": count_by(records, "constructibility"),
        "by_profile": count_by(records, "profile"),
        "by_gate_pack": count_by(records, "gate_pack"),
    }
