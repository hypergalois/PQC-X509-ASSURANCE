"""Policy metadata and mode-aware evaluation helpers."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List, Mapping


VALID_OWNERS = {
    "ca-preissuance",
    "artifact-importer",
    "runtime-consumer",
}
VALID_DETECTOR_KINDS = {
    "structural",
    "policy",
    "import-crypto",
    "heuristic",
}
VALID_NORMATIVE_STRENGTHS = {
    "must",
    "should",
    "policy",
}
VALID_PROFILES = {"pkix-core"}
VALID_CONSTRUCTIBILITY = {
    "covered",
    "planned",
    "external-only",
}
VALID_GATE_PACKS = {
    "ca-certificate-profile",
    "ca-spki-public-key",
    "import-private-key",
}
VALID_MODES = ("deployable", "strict")
VALID_MODE_ACTIONS = {"block", "warn", "ignore"}

GATE_PACK_EXPECTATIONS = {
    "ca-certificate-profile": {
        "owner": "ca-preissuance",
        "stage": "certificate/profile",
    },
    "ca-spki-public-key": {
        "owner": "ca-preissuance",
        "stage": "SPKI/public-key",
    },
    "import-private-key": {
        "owner": "artifact-importer",
        "stage": "private-key-container/import",
    },
}


def validate_requirement_policy(record: Mapping[str, Any], path: str) -> None:
    requirement_id = str(record.get("id", "<unknown>"))
    owner = str(record.get("owner"))
    detector_kind = str(record.get("detector_kind"))
    normative_strength = str(record.get("normative_strength"))
    constructibility = str(record.get("constructibility"))
    profile = str(record.get("profile"))
    gate_pack = str(record.get("gate_pack"))
    justification = str(record.get("justification", "")).strip()
    mode_action = record.get("mode_action")

    if owner not in VALID_OWNERS:
        raise ValueError(f"{path}: requirement {requirement_id} owner must be one of {sorted(VALID_OWNERS)}")
    if detector_kind not in VALID_DETECTOR_KINDS:
        raise ValueError(
            f"{path}: requirement {requirement_id} detector_kind must be one of {sorted(VALID_DETECTOR_KINDS)}"
        )
    if normative_strength not in VALID_NORMATIVE_STRENGTHS:
        raise ValueError(
            f"{path}: requirement {requirement_id} normative_strength must be one of {sorted(VALID_NORMATIVE_STRENGTHS)}"
        )
    if constructibility not in VALID_CONSTRUCTIBILITY:
        raise ValueError(
            f"{path}: requirement {requirement_id} constructibility must be one of {sorted(VALID_CONSTRUCTIBILITY)}"
        )
    if profile not in VALID_PROFILES:
        raise ValueError(
            f"{path}: requirement {requirement_id} profile must be one of {sorted(VALID_PROFILES)}"
        )
    if gate_pack not in VALID_GATE_PACKS:
        raise ValueError(
            f"{path}: requirement {requirement_id} gate_pack must be one of {sorted(VALID_GATE_PACKS)}"
        )
    if not justification:
        raise ValueError(f"{path}: requirement {requirement_id} justification must be a non-empty string")
    if not isinstance(mode_action, dict):
        raise ValueError(f"{path}: requirement {requirement_id} mode_action must be an object")
    if set(mode_action) != set(VALID_MODES):
        raise ValueError(
            f"{path}: requirement {requirement_id} mode_action must contain exactly {list(VALID_MODES)}"
        )
    for mode in VALID_MODES:
        action = str(mode_action.get(mode))
        if action not in VALID_MODE_ACTIONS:
            raise ValueError(
                f"{path}: requirement {requirement_id} mode_action[{mode}] must be one of {sorted(VALID_MODE_ACTIONS)}"
            )
    expected = GATE_PACK_EXPECTATIONS.get(gate_pack, {})
    if owner != expected.get("owner") or str(record.get("stage")) != expected.get("stage"):
        raise ValueError(
            f"{path}: requirement {requirement_id} gate_pack {gate_pack} must map to "
            f"owner={expected.get('owner')} and stage={expected.get('stage')}"
        )


def requirement_action(requirement: Mapping[str, Any], mode: str) -> str:
    if mode not in VALID_MODES:
        raise ValueError(f"unsupported policy mode: {mode}")
    mode_action = requirement.get("mode_action")
    if not isinstance(mode_action, Mapping):
        raise ValueError(f"requirement {requirement.get('id')} missing mode_action")
    action = str(mode_action.get(mode))
    if action not in VALID_MODE_ACTIONS:
        raise ValueError(
            f"requirement {requirement.get('id')} has invalid mode action {action!r} for {mode}"
        )
    return action


def applicable_requirements(
    requirements: Iterable[Mapping[str, Any]],
    *,
    profile: str,
    algorithm: str | None = None,
    stage: str | None = None,
) -> List[Dict[str, Any]]:
    selected = []
    for requirement in requirements:
        if str(requirement.get("profile")) != profile:
            continue
        if algorithm is not None and str(requirement.get("algorithm")) != algorithm:
            continue
        if stage is not None and str(requirement.get("stage")) != stage:
            continue
        selected.append(dict(requirement))
    return selected


def artifact_policy_context(
    record: Mapping[str, Any],
    requirements: Iterable[Mapping[str, Any]],
    *,
    profile: str,
) -> Dict[str, Any]:
    applicable = applicable_requirements(
        requirements,
        profile=profile,
        algorithm=str(record.get("algorithm", "")),
        stage=str(record.get("stage", "")),
    )
    owners = sorted({str(requirement.get("owner")) for requirement in applicable})
    owner = owners[0] if len(owners) == 1 else ("mixed" if owners else "unassigned")
    return {
        "profile": profile,
        "owner": owner,
        "owners": owners,
        "applicable_requirement_ids": sorted(str(requirement.get("id")) for requirement in applicable),
    }


def evaluate_policy(
    findings: List[Dict[str, Any]],
    record: Mapping[str, Any],
    requirements: Iterable[Mapping[str, Any]],
    *,
    mode: str,
    profile: str,
) -> Dict[str, Any]:
    requirement_index = {
        str(requirement.get("id")): dict(requirement)
        for requirement in applicable_requirements(
            requirements,
            profile=profile,
            algorithm=str(record.get("algorithm", "")),
            stage=str(record.get("stage", "")),
        )
    }
    context = artifact_policy_context(record, requirements, profile=profile)
    blocking_findings: List[Dict[str, Any]] = []
    warning_findings: List[Dict[str, Any]] = []
    ignored_findings: List[Dict[str, Any]] = []

    for finding in findings:
        if str(finding.get("status")) != "error":
            continue
        requirement_id = str(finding.get("requirement_id", ""))
        requirement = requirement_index.get(requirement_id)
        if requirement is None:
            raise ValueError(
                f"finding {requirement_id} for artifact {record.get('artifact_id')} "
                f"does not map to an applicable requirement under profile {profile}"
            )
        action = requirement_action(requirement, mode)
        enriched = {
            **finding,
            "policy_action": action,
            "owner": requirement.get("owner"),
            "normative_strength": requirement.get("normative_strength"),
        }
        if action == "block":
            blocking_findings.append(enriched)
        elif action == "warn":
            warning_findings.append(enriched)
        else:
            ignored_findings.append(enriched)

    blocking_ids = _ordered_unique(blocking_findings)
    warning_ids = _ordered_unique(warning_findings)
    ignored_ids = _ordered_unique(ignored_findings)
    if blocking_findings:
        final_disposition = "block"
    elif warning_findings:
        final_disposition = "warn"
    else:
        final_disposition = "pass"

    return {
        **context,
        "mode": mode,
        "blocking_findings": blocking_findings,
        "warning_findings": warning_findings,
        "ignored_findings": ignored_findings,
        "blocking_requirement_ids": blocking_ids,
        "warning_requirement_ids": warning_ids,
        "ignored_requirement_ids": ignored_ids,
        "first_blocking_requirement": blocking_ids[0] if blocking_ids else None,
        "first_warning_requirement": warning_ids[0] if warning_ids else None,
        "blocking_count": len(blocking_findings),
        "warning_count": len(warning_findings),
        "ignored_count": len(ignored_findings),
        "final_disposition": final_disposition,
    }


def _ordered_unique(findings: List[Mapping[str, Any]]) -> List[str]:
    seen = set()
    ordered: List[str] = []
    for finding in findings:
        requirement_id = str(finding.get("requirement_id"))
        if requirement_id in seen:
            continue
        seen.add(requirement_id)
        ordered.append(requirement_id)
    return ordered


def policy_matrix_rows(requirements: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    rows = []
    for requirement in requirements:
        rows.append(
            {
                "id": requirement.get("id"),
                "algorithm": requirement.get("algorithm"),
                "artifact_type": requirement.get("artifact_type"),
                "stage": requirement.get("stage"),
                "profile": requirement.get("profile"),
                "owner": requirement.get("owner"),
                "gate_pack": requirement.get("gate_pack"),
                "detector_kind": requirement.get("detector_kind"),
                "normative_strength": requirement.get("normative_strength"),
                "constructibility": requirement.get("constructibility"),
                "baseline_status": requirement.get("baseline_status"),
                "expected_detector": requirement.get("expected_detector"),
                "deployable_action": requirement_action(requirement, "deployable"),
                "strict_action": requirement_action(requirement, "strict"),
                "justification": requirement.get("justification"),
            }
        )
    return rows


def policy_summary(
    requirements: Iterable[Mapping[str, Any]],
    *,
    profile: str,
    mode: str,
) -> Dict[str, Any]:
    selected = applicable_requirements(requirements, profile=profile)
    return {
        "profile": profile,
        "mode": mode,
        "requirement_count": len(selected),
        "by_algorithm": _count(selected, "algorithm"),
        "by_stage": _count(selected, "stage"),
        "by_owner": _count(selected, "owner"),
        "by_detector_kind": _count(selected, "detector_kind"),
        "by_normative_strength": _count(selected, "normative_strength"),
        "by_constructibility": _count(selected, "constructibility"),
        "by_action": dict(
            Counter(requirement_action(requirement, mode) for requirement in selected)
        ),
        "blocking_requirements": sorted(
            str(requirement.get("id"))
            for requirement in selected
            if requirement_action(requirement, mode) == "block"
        ),
        "warning_requirements": sorted(
            str(requirement.get("id"))
            for requirement in selected
            if requirement_action(requirement, mode) == "warn"
        ),
        "ignored_requirements": sorted(
            str(requirement.get("id"))
            for requirement in selected
            if requirement_action(requirement, mode) == "ignore"
        ),
    }


def stage_owner_summary(
    requirements: Iterable[Mapping[str, Any]],
    *,
    profile: str,
) -> Dict[str, Any]:
    selected = applicable_requirements(requirements, profile=profile)
    rows = []
    grouped: Dict[tuple[str, str], List[Mapping[str, Any]]] = defaultdict(list)
    for requirement in selected:
        grouped[(str(requirement.get("stage")), str(requirement.get("owner")))].append(requirement)
    for (stage, owner), entries in sorted(grouped.items()):
        rows.append(
            {
                "stage": stage,
                "owner": owner,
                "requirement_count": len(entries),
                "deployable_action_counts": dict(
                    Counter(requirement_action(entry, "deployable") for entry in entries)
                ),
                "strict_action_counts": dict(
                    Counter(requirement_action(entry, "strict") for entry in entries)
                ),
                "requirement_ids": sorted(str(entry.get("id")) for entry in entries),
            }
        )
    return {
        "profile": profile,
        "requirement_count": len(selected),
        "by_stage": _count(selected, "stage"),
        "by_owner": _count(selected, "owner"),
        "rows": rows,
    }


def _count(records: Iterable[Mapping[str, Any]], field: str) -> Dict[str, int]:
    return dict(Counter(str(record.get(field, "unknown")) for record in records))
