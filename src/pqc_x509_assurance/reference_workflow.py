"""Package the PQ X.509 assurance artifact as an operational workflow."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List

from .paths import project_root
from .policy import VALID_OWNERS, applicable_requirements, requirement_action
from .requirements import load_registry, requirements


OWNER_TITLES = {
    "ca-preissuance": "CA pre-issuance gate",
    "artifact-importer": "Artifact importer gate",
    "runtime-consumer": "Runtime consumer boundary",
}

OWNER_SUMMARIES = {
    "ca-preissuance": "What the CA inspects before issuance across certificate/profile and SPKI/public-key gates.",
    "artifact-importer": "What the importer validates before accepting a private-key container for use.",
    "runtime-consumer": "Explicit boundary information for runtime consumers that remain outside executable scope.",
}

STAGE_NOTES = {
    "SPKI/public-key": "Validate public-key structure and profile before issuance.",
    "certificate/profile": "Validate certificate semantics and PKIX policy before issuance.",
    "private-key-container/import": "Validate imported private-key containers before use.",
}

OWNER_COMMANDS = {
    "ca-preissuance": {
        "strict": [
            "./experiments/run_extended.sh --mode strict",
            "./experiments/run_coverage.sh --mode strict",
        ],
        "deployable": [
            "./experiments/run_extended.sh --mode deployable",
            "./experiments/run_coverage.sh --mode deployable",
        ],
    },
    "artifact-importer": {
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
    "runtime-consumer": {
        "strict": [],
        "deployable": [],
    },
}

MODE_OUTPUTS = {
    "strict": {
        "extended_summary": "results/extended_registry_summary.json",
        "policy_summary": "results/policy_summary_strict.json",
        "certificate_spki_coverage": "results/certificate_spki_coverage.json",
        "private_key_coverage": "results/private_key_coverage.json",
    },
    "deployable": {
        "extended_summary": "results/extended_registry_summary_deployable.json",
        "policy_summary": "results/policy_summary_deployable.json",
        "certificate_spki_coverage": "results/certificate_spki_coverage_deployable.json",
        "private_key_coverage": "results/private_key_coverage_deployable.json",
    },
}


def build_reference_workflow(registry_path: Path, *, profile: str) -> Dict[str, Any]:
    registry = load_registry(registry_path)
    selected = applicable_requirements(requirements(registry), profile=profile)
    owner_rows = []
    for owner in sorted(VALID_OWNERS):
        owner_requirements = [req for req in selected if str(req.get("owner")) == owner]
        stage_rows = []
        for stage in sorted({str(req.get("stage")) for req in owner_requirements}):
            stage_requirements = [
                req for req in owner_requirements if str(req.get("stage")) == stage
            ]
            stage_rows.append(
                {
                    "stage": stage,
                    "note": STAGE_NOTES.get(stage, ""),
                    "requirement_count": len(stage_requirements),
                    "requirement_ids": sorted(str(req.get("id")) for req in stage_requirements),
                    "actions": {
                        "strict": _count_actions(stage_requirements, "strict"),
                        "deployable": _count_actions(stage_requirements, "deployable"),
                    },
                }
            )
        owner_rows.append(
            {
                "owner": owner,
                "title": OWNER_TITLES.get(owner, owner),
                "requirement_count": len(owner_requirements),
                "status": "active" if owner_requirements else "out-of-scope",
                "commands": OWNER_COMMANDS[owner],
                "modes": {
                    "strict": {
                        "blocking_requirements": sorted(
                            str(req.get("id"))
                            for req in owner_requirements
                            if requirement_action(req, "strict") == "block"
                        ),
                        "warning_requirements": sorted(
                            str(req.get("id"))
                            for req in owner_requirements
                            if requirement_action(req, "strict") == "warn"
                        ),
                    },
                    "deployable": {
                        "blocking_requirements": sorted(
                            str(req.get("id"))
                            for req in owner_requirements
                            if requirement_action(req, "deployable") == "block"
                        ),
                        "warning_requirements": sorted(
                            str(req.get("id"))
                            for req in owner_requirements
                            if requirement_action(req, "deployable") == "warn"
                        ),
                    },
                },
                "stages": stage_rows,
                "note": (
                    "No active requirements are currently assigned to runtime-consumer in pkix-core; runtime remains outside the executable scope of this artifact."
                    if owner == "runtime-consumer" and not owner_requirements
                    else ""
                ),
            }
        )

    return {
        "profile": profile,
        "owners": owner_rows,
        "shared_outputs": {
            "policy_matrix": "results/policy_matrix.csv",
            "stage_owner_summary": "results/stage_owner_summary.json",
            "baseline_compare": "results/baseline_vs_extended_certificate_report.json",
        },
        "mode_outputs": MODE_OUTPUTS,
        "notes": [
            "Baseline comparison remains supporting evidence, not the primary workflow output.",
            "CA pre-issuance owns certificate/profile and SPKI/public-key gates in pkix-core.",
            "Artifact importer owns private-key-container/import checks in pkix-core.",
        ],
    }


def render_reference_workflow_markdown(workflow: Dict[str, Any]) -> str:
    lines = [
        "# Reference Workflow",
        "",
        f"Profile: `{workflow['profile']}`",
        "",
        "This workflow packages the current artifact as an operational recipe by owner and stage.",
        "",
        "## Shared Outputs",
        "",
    ]
    for label, path in workflow["shared_outputs"].items():
        lines.append(f"- `{label}`: `{path}`")
    lines.append("")
    lines.append("## Mode Outputs")
    lines.append("")
    for mode, outputs in workflow["mode_outputs"].items():
        lines.append(f"### {mode}")
        lines.append("")
        for label, path in outputs.items():
            lines.append(f"- `{label}`: `{path}`")
        lines.append("")
    for owner in workflow["owners"]:
        lines.append(f"## {owner['title']}")
        lines.append("")
        lines.append(f"- owner: `{owner['owner']}`")
        lines.append(f"- status: `{owner['status']}`")
        lines.append(f"- requirement_count: {owner['requirement_count']}")
        lines.append(f"- operator_focus: {OWNER_SUMMARIES.get(owner['owner'], owner['title'])}")
        if owner["note"]:
            lines.append(f"- note: {owner['note']}")
        lines.append("- commands:")
        for mode in ("strict", "deployable"):
            commands = owner["commands"][mode]
            if commands:
                lines.append(f"  - `{mode}`:")
                for command in commands:
                    lines.append(f"    - `{command}`")
            else:
                lines.append(f"  - `{mode}`: none")
        lines.append("- stages:")
        if owner["stages"]:
            for stage in owner["stages"]:
                lines.append(f"  - `{stage['stage']}`: {stage['note']}")
                lines.append(f"    - requirements: {stage['requirement_count']}")
                lines.append(f"    - requirement_ids: {', '.join(stage['requirement_ids'])}")
                lines.append(
                    f"    - strict actions: {json.dumps(stage['actions']['strict'], sort_keys=True)}"
                )
                lines.append(
                    f"    - deployable actions: {json.dumps(stage['actions']['deployable'], sort_keys=True)}"
                )
        else:
            lines.append("  - none")
        lines.append("")
    lines.append("## Notes")
    lines.append("")
    for note in workflow["notes"]:
        lines.append(f"- {note}")
    lines.append("")
    return "\n".join(lines)


def _count_actions(rows: Iterable[Dict[str, Any]], mode: str) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for row in rows:
        action = requirement_action(row, mode)
        counts[action] = counts.get(action, 0) + 1
    return counts


def main(argv: List[str] | None = None) -> int:
    root = project_root()
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", type=Path, default=root / "requirements.json")
    parser.add_argument("--profile", default="pkix-core")
    parser.add_argument("--out-dir", type=Path, default=root / "results")
    parser.add_argument("--docs-dir", type=Path, default=root / "docs")
    args = parser.parse_args(argv)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    args.docs_dir.mkdir(parents=True, exist_ok=True)
    workflow = build_reference_workflow(args.registry, profile=args.profile)
    json_path = args.out_dir / "reference_workflow.json"
    md_path = args.docs_dir / "reference-workflow.md"
    json_path.write_text(json.dumps(workflow, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(render_reference_workflow_markdown(workflow), encoding="utf-8")
    print(f"wrote {json_path}")
    print(f"wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
