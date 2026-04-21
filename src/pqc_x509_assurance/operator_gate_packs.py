"""Emit operator-facing gate packs for CA and importer workflows."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping

from .policy import (
    VALID_GATE_PACKS,
    applicable_requirements,
    requirement_action,
)
from .requirements import load_registry, requirements


GATE_PACK_TITLES = {
    "ca-certificate-profile": "CA certificate/profile gate",
    "ca-spki-public-key": "CA SPKI/public-key gate",
    "import-private-key": "Importer private-key gate",
}

GATE_PACK_PURPOSES = {
    "ca-certificate-profile": (
        "What the CA inspects in the certificate/profile gate before issuance, "
        "including keyUsage, signatureAlgorithm, and PKIX algorithm-policy checks."
    ),
    "ca-spki-public-key": (
        "What the CA inspects in SubjectPublicKeyInfo before issuance, including "
        "AlgorithmIdentifier correctness and parameter-set sizing."
    ),
    "import-private-key": (
        "What the importer inspects before private-key acceptance, including "
        "CHOICE form, lengths, and seed/expanded consistency checks."
    ),
}

GATE_PACK_OWNER = {
    "ca-certificate-profile": "ca-preissuance",
    "ca-spki-public-key": "ca-preissuance",
    "import-private-key": "artifact-importer",
}

GATE_PACK_STAGE = {
    "ca-certificate-profile": "certificate/profile",
    "ca-spki-public-key": "SPKI/public-key",
    "import-private-key": "private-key-container/import",
}

GATE_PACK_COMMANDS = {
    "ca-certificate-profile": {
        "strict": [
            "./experiments/run_extended.sh --mode strict",
            "./experiments/run_coverage.sh --mode strict",
        ],
        "deployable": [
            "./experiments/run_extended.sh --mode deployable",
            "./experiments/run_coverage.sh --mode deployable",
        ],
    },
    "ca-spki-public-key": {
        "strict": [
            "./experiments/run_extended.sh --mode strict",
            "./experiments/run_coverage.sh --mode strict",
        ],
        "deployable": [
            "./experiments/run_extended.sh --mode deployable",
            "./experiments/run_coverage.sh --mode deployable",
        ],
    },
    "import-private-key": {
        "strict": [
            "./experiments/build_libcrux_import_check.sh",
            "./experiments/run_extended.sh --mode strict",
            "./experiments/run_private_key_coverage.sh --mode strict",
        ],
        "deployable": [
            "./experiments/build_libcrux_import_check.sh",
            "./experiments/run_extended.sh --mode deployable",
            "./experiments/run_private_key_coverage.sh --mode deployable",
        ],
    },
}

GATE_PACK_OUTPUTS = {
    "ca-certificate-profile": {
        "strict": [
            "results/extended_registry_summary.json",
            "results/policy_summary_strict.json",
            "results/certificate_spki_coverage.json",
            "results/operator_readiness_summary.json",
        ],
        "deployable": [
            "results/extended_registry_summary_deployable.json",
            "results/policy_summary_deployable.json",
            "results/certificate_spki_coverage_deployable.json",
            "results/operator_readiness_summary.json",
        ],
    },
    "ca-spki-public-key": {
        "strict": [
            "results/extended_registry_summary.json",
            "results/policy_summary_strict.json",
            "results/certificate_spki_coverage.json",
            "results/operator_gate_matrix.json",
        ],
        "deployable": [
            "results/extended_registry_summary_deployable.json",
            "results/policy_summary_deployable.json",
            "results/certificate_spki_coverage_deployable.json",
            "results/operator_gate_matrix.json",
        ],
    },
    "import-private-key": {
        "strict": [
            "results/extended_registry_summary.json",
            "results/policy_summary_strict.json",
            "results/private_key_coverage.json",
            "results/operator_gate_matrix.json",
        ],
        "deployable": [
            "results/extended_registry_summary_deployable.json",
            "results/policy_summary_deployable.json",
            "results/private_key_coverage_deployable.json",
            "results/operator_gate_matrix.json",
        ],
    },
}

RUNTIME_BOUNDARY_NOTE = (
    "runtime-consumer remains explicit as a boundary in pkix-core, but no active "
    "runtime requirements are executable in this repository snapshot."
)


def build_operator_gate_pack_report(registry_path: Path, *, profile: str) -> Dict[str, Any]:
    registry = load_registry(registry_path)
    selected = applicable_requirements(requirements(registry), profile=profile)
    rows = []
    gate_packs = []
    for gate_pack in sorted(VALID_GATE_PACKS):
        pack_requirements = [
            requirement
            for requirement in selected
            if str(requirement.get("gate_pack")) == gate_pack
        ]
        rows.extend(_pack_rows(pack_requirements))
        gate_packs.append(
            {
                "gate_pack": gate_pack,
                "title": GATE_PACK_TITLES[gate_pack],
                "purpose": GATE_PACK_PURPOSES[gate_pack],
                "owner": GATE_PACK_OWNER[gate_pack],
                "stage": GATE_PACK_STAGE[gate_pack],
                "requirement_count": len(pack_requirements),
                "requirement_ids": sorted(str(requirement.get("id")) for requirement in pack_requirements),
                "strict": _mode_block_warning_summary(pack_requirements, "strict"),
                "deployable": _mode_block_warning_summary(pack_requirements, "deployable"),
                "commands": GATE_PACK_COMMANDS[gate_pack],
                "inspect_outputs": GATE_PACK_OUTPUTS[gate_pack],
            }
        )
    readiness = {
        "profile": profile,
        "status": "operator-gate-packs-locked",
        "default_operator_mode": "deployable",
        "reference_mode": "strict",
        "gate_pack_count": len(gate_packs),
        "requirement_count": len(selected),
        "by_gate_pack": dict(Counter(str(requirement.get("gate_pack")) for requirement in selected)),
        "gate_packs": gate_packs,
        "runtime_boundary": {
            "owner": "runtime-consumer",
            "status": "out-of-scope",
            "note": RUNTIME_BOUNDARY_NOTE,
        },
        "notes": [
            "CA guidance defaults to deployable mode so operator runs align with low-noise issuance gating.",
            "Strict mode remains the assurance-maximizing reference and should be used for deep audits or pre-release checks.",
            "The only non-blocking deployable requirement in the current registry is MLKEM-SPKI-ENCODE-DECODE-IDENTITY.",
        ],
    }
    return {
        "profile": profile,
        "rows": rows,
        "gate_packs": gate_packs,
        "readiness": readiness,
    }


def render_operator_playbook(report: Mapping[str, Any]) -> str:
    lines = [
        "# Operational Workflow Summary",
        "",
        f"Profile: `{report['profile']}`",
        "",
        "This document summarizes the executable workflow for the current PKIX core repository snapshot.",
        "",
        f"- runtime boundary: {report['readiness']['runtime_boundary']['note']}",
        "- default CA mode: `deployable`",
        "- reference assurance mode: `strict`",
        "- operator reading rule: start from the gate-pack you own, then inspect the listed outputs for that mode",
        "",
    ]
    for gate_pack in report["gate_packs"]:
        lines.extend(
            [
                f"## {gate_pack['title']}",
                "",
                f"- gate_pack: `{gate_pack['gate_pack']}`",
                f"- intended_owner: `{gate_pack['owner']}`",
                f"- stage: `{gate_pack['stage']}`",
                f"- purpose: {gate_pack['purpose']}",
                f"- requirement_count: {gate_pack['requirement_count']}",
                f"- requirement_ids: {', '.join(gate_pack['requirement_ids'])}",
                f"- operator_question: what should `{gate_pack['owner']}` inspect before this gate passes?",
                "- commands:",
            ]
        )
        for mode in ("deployable", "strict"):
            lines.append(f"  - `{mode}`:")
            for command in gate_pack["commands"][mode]:
                lines.append(f"    - `{command}`")
        lines.extend(
            [
                "- blocking_vs_warning:",
                (
                    f"  - deployable: blocks {gate_pack['deployable']['block_count']} "
                    f"requirements and warns on {gate_pack['deployable']['warn_count']}"
                ),
                (
                    f"  - strict: blocks {gate_pack['strict']['block_count']} "
                    f"requirements and warns on {gate_pack['strict']['warn_count']}"
                ),
                "- inspect_outputs:",
            ]
        )
        for mode in ("deployable", "strict"):
            lines.append(f"  - `{mode}`:")
            for path in gate_pack["inspect_outputs"][mode]:
                lines.append(f"    - `{path}`")
        lines.append("")
    lines.extend(["## Notes", ""])
    for note in report["readiness"]["notes"]:
        lines.append(f"- {note}")
    lines.append("")
    return "\n".join(lines)


def _pack_rows(pack_requirements: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    rows = []
    for requirement in pack_requirements:
        rows.append(
            {
                "gate_pack": requirement.get("gate_pack"),
                "id": requirement.get("id"),
                "algorithm": requirement.get("algorithm"),
                "artifact_type": requirement.get("artifact_type"),
                "stage": requirement.get("stage"),
                "owner": requirement.get("owner"),
                "fault_family": requirement.get("fault_family"),
                "baseline_status": requirement.get("baseline_status"),
                "expected_detector": requirement.get("expected_detector"),
                "deployable_action": requirement_action(requirement, "deployable"),
                "strict_action": requirement_action(requirement, "strict"),
            }
        )
    return rows


def _mode_block_warning_summary(
    pack_requirements: Iterable[Mapping[str, Any]],
    mode: str,
) -> Dict[str, Any]:
    blocking = []
    warnings = []
    ignored = []
    for requirement in pack_requirements:
        action = requirement_action(requirement, mode)
        if action == "block":
            blocking.append(str(requirement.get("id")))
        elif action == "warn":
            warnings.append(str(requirement.get("id")))
        else:
            ignored.append(str(requirement.get("id")))
    return {
        "block_count": len(blocking),
        "warn_count": len(warnings),
        "ignore_count": len(ignored),
        "blocking_requirement_ids": sorted(blocking),
        "warning_requirement_ids": sorted(warnings),
        "ignored_requirement_ids": sorted(ignored),
    }


def write_operator_gate_outputs(report: Mapping[str, Any], root: Path) -> Dict[str, Path]:
    results_dir = root / "results"
    docs_dir = root / "docs"
    results_dir.mkdir(parents=True, exist_ok=True)
    docs_dir.mkdir(parents=True, exist_ok=True)

    matrix_json = results_dir / "operator_gate_matrix.json"
    matrix_csv = results_dir / "operator_gate_matrix.csv"
    readiness_json = results_dir / "operator_readiness_summary.json"
    playbook_md = docs_dir / "operator-playbook.md"

    matrix_json.write_text(
        json.dumps(
            {
                "profile": report["profile"],
                "gate_packs": report["gate_packs"],
                "rows": report["rows"],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    readiness_json.write_text(
        json.dumps(report["readiness"], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with matrix_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "gate_pack",
                "id",
                "algorithm",
                "artifact_type",
                "stage",
                "owner",
                "fault_family",
                "baseline_status",
                "expected_detector",
                "deployable_action",
                "strict_action",
            ],
        )
        writer.writeheader()
        writer.writerows(report["rows"])
    playbook_md.write_text(render_operator_playbook(report), encoding="utf-8")
    return {
        "matrix_json": matrix_json,
        "matrix_csv": matrix_csv,
        "readiness_json": readiness_json,
        "playbook_md": playbook_md,
    }


def main(argv: List[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", type=Path, default=root / "requirements.json")
    parser.add_argument("--profile", default="pkix-core")
    args = parser.parse_args(argv)

    report = build_operator_gate_pack_report(args.registry, profile=args.profile)
    outputs = write_operator_gate_outputs(report, root)
    for path in outputs.values():
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
