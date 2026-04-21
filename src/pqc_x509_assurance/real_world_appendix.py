"""Extract and ledger a bounded public appendix corpus."""

from __future__ import annotations

import argparse
import json
import subprocess
import zipfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

from .corpus_manifest import sha256


REPO_URL = "https://github.com/IETF-Hackathon/pqc-certificates"
THIRD_PARTY_REPO = Path("third_party/pqc-certificates-main")


@dataclass(frozen=True)
class AppendixArtifact:
    artifact_id: str
    provider: str
    zip_relpath: str
    zip_member: str
    output_relpath: str
    artifact_type: str
    algorithm: str
    parameter_set: str
    stage: str
    selection_reason: str

    def manifest_record(
        self,
        root: Path,
        repo_commit: str,
        access_date: str,
        zip_digest: str,
    ) -> Dict[str, Any]:
        output_path = root / self.output_relpath
        return {
            "artifact_id": self.artifact_id,
            "artifact_type": self.artifact_type,
            "algorithm": self.algorithm,
            "parameter_set": self.parameter_set,
            "path": self.output_relpath,
            "provider": self.provider,
            "stage": self.stage,
            "validity": "valid",
            "fault_family": "none",
            "mutation": "none",
            "mutation_family": [],
            "expected_detection": [],
            "appendix": True,
            "selection_reason": self.selection_reason,
            "sha256": sha256(output_path),
            "source": (
                "Public appendix artifact extracted from "
                f"{REPO_URL} commit {repo_commit}"
            ),
            "source_locators": [
                REPO_URL,
                f"access-date:{access_date}",
                f"commit:{repo_commit}",
                f"zip:{self.zip_relpath}",
                f"zip-sha256:{zip_digest}",
                f"member:{self.zip_member}",
                "license:third_party/pqc-certificates-main/license.txt",
            ],
        }


def _private_artifact(
    *,
    artifact_id: str,
    provider: str,
    zip_relpath: str,
    zip_member: str,
    output_relpath: str,
    algorithm: str,
    parameter_set: str,
    selection_reason: str,
) -> AppendixArtifact:
    return AppendixArtifact(
        artifact_id=artifact_id,
        provider=provider,
        zip_relpath=zip_relpath,
        zip_member=zip_member,
        output_relpath=output_relpath,
        artifact_type="private-key-container",
        algorithm=algorithm,
        parameter_set=parameter_set,
        stage="private-key-container/import",
        selection_reason=selection_reason,
    )


def _ossl35_extremal_private_artifacts() -> List[AppendixArtifact]:
    zip_relpath = "providers/ossl35/artifacts_certs_r5.zip"
    return [
        _private_artifact(
            artifact_id="appendix-ossl35-mldsa44-seed-key",
            provider="ossl35",
            zip_relpath=zip_relpath,
            zip_member="ml-dsa-44-2.16.840.1.101.3.4.3.17_seed_priv.der",
            output_relpath="corpus/appendix/public_repo/ossl35/ossl35_ml_dsa_44_seed_priv.der",
            algorithm="ML-DSA",
            parameter_set="ML-DSA-44",
            selection_reason="low-parameter pure ML-DSA seed-only private key from ossl35 to cover importer behavior at the low end",
        ),
        _private_artifact(
            artifact_id="appendix-ossl35-mldsa44-expanded-key",
            provider="ossl35",
            zip_relpath=zip_relpath,
            zip_member="ml-dsa-44-2.16.840.1.101.3.4.3.17_expandedkey_priv.der",
            output_relpath="corpus/appendix/public_repo/ossl35/ossl35_ml_dsa_44_expandedkey_priv.der",
            algorithm="ML-DSA",
            parameter_set="ML-DSA-44",
            selection_reason="low-parameter pure ML-DSA expanded-key private key from ossl35 to complement seed-only import coverage",
        ),
        _private_artifact(
            artifact_id="appendix-ossl35-mldsa44-both-key",
            provider="ossl35",
            zip_relpath=zip_relpath,
            zip_member="ml-dsa-44-2.16.840.1.101.3.4.3.17_both_priv.der",
            output_relpath="corpus/appendix/public_repo/ossl35/ossl35_ml_dsa_44_both_priv.der",
            algorithm="ML-DSA",
            parameter_set="ML-DSA-44",
            selection_reason="low-parameter pure ML-DSA both-form private key from ossl35 to cover seed-expanded consistency parsing",
        ),
        _private_artifact(
            artifact_id="appendix-ossl35-mldsa87-seed-key",
            provider="ossl35",
            zip_relpath=zip_relpath,
            zip_member="ml-dsa-87-2.16.840.1.101.3.4.3.19_seed_priv.der",
            output_relpath="corpus/appendix/public_repo/ossl35/ossl35_ml_dsa_87_seed_priv.der",
            algorithm="ML-DSA",
            parameter_set="ML-DSA-87",
            selection_reason="high-parameter pure ML-DSA seed-only private key from ossl35 to show importer coverage at the high end",
        ),
        _private_artifact(
            artifact_id="appendix-ossl35-mldsa87-expanded-key",
            provider="ossl35",
            zip_relpath=zip_relpath,
            zip_member="ml-dsa-87-2.16.840.1.101.3.4.3.19_expandedkey_priv.der",
            output_relpath="corpus/appendix/public_repo/ossl35/ossl35_ml_dsa_87_expandedkey_priv.der",
            algorithm="ML-DSA",
            parameter_set="ML-DSA-87",
            selection_reason="high-parameter pure ML-DSA expanded-key private key from ossl35 to close representation coverage at the high end",
        ),
        _private_artifact(
            artifact_id="appendix-ossl35-mldsa87-both-key",
            provider="ossl35",
            zip_relpath=zip_relpath,
            zip_member="ml-dsa-87-2.16.840.1.101.3.4.3.19_both_priv.der",
            output_relpath="corpus/appendix/public_repo/ossl35/ossl35_ml_dsa_87_both_priv.der",
            algorithm="ML-DSA",
            parameter_set="ML-DSA-87",
            selection_reason="high-parameter pure ML-DSA both-form private key from ossl35 to pair consistency checks with the highest parameter set",
        ),
        _private_artifact(
            artifact_id="appendix-ossl35-mlkem512-seed-key",
            provider="ossl35",
            zip_relpath=zip_relpath,
            zip_member="ml-kem-512-2.16.840.1.101.3.4.4.1_seed_priv.der",
            output_relpath="corpus/appendix/public_repo/ossl35/ossl35_ml_kem_512_seed_priv.der",
            algorithm="ML-KEM",
            parameter_set="ML-KEM-512",
            selection_reason="low-parameter pure ML-KEM seed-only private key from ossl35 to widen importer coverage beyond the mid-level parameter set",
        ),
        _private_artifact(
            artifact_id="appendix-ossl35-mlkem512-expanded-key",
            provider="ossl35",
            zip_relpath=zip_relpath,
            zip_member="ml-kem-512-2.16.840.1.101.3.4.4.1_expandedkey_priv.der",
            output_relpath="corpus/appendix/public_repo/ossl35/ossl35_ml_kem_512_expandedkey_priv.der",
            algorithm="ML-KEM",
            parameter_set="ML-KEM-512",
            selection_reason="low-parameter pure ML-KEM expanded-key private key from ossl35 to exercise hash-check parsing outside the default set",
        ),
        _private_artifact(
            artifact_id="appendix-ossl35-mlkem512-both-key",
            provider="ossl35",
            zip_relpath=zip_relpath,
            zip_member="ml-kem-512-2.16.840.1.101.3.4.4.1_both_priv.der",
            output_relpath="corpus/appendix/public_repo/ossl35/ossl35_ml_kem_512_both_priv.der",
            algorithm="ML-KEM",
            parameter_set="ML-KEM-512",
            selection_reason="low-parameter pure ML-KEM both-form private key from ossl35 to cover seed-expanded consistency at the low end",
        ),
        _private_artifact(
            artifact_id="appendix-ossl35-mlkem1024-seed-key",
            provider="ossl35",
            zip_relpath=zip_relpath,
            zip_member="ml-kem-1024-2.16.840.1.101.3.4.4.3_seed_priv.der",
            output_relpath="corpus/appendix/public_repo/ossl35/ossl35_ml_kem_1024_seed_priv.der",
            algorithm="ML-KEM",
            parameter_set="ML-KEM-1024",
            selection_reason="high-parameter pure ML-KEM seed-only private key from ossl35 to complete parameter-set coverage for importer behavior",
        ),
        _private_artifact(
            artifact_id="appendix-ossl35-mlkem1024-expanded-key",
            provider="ossl35",
            zip_relpath=zip_relpath,
            zip_member="ml-kem-1024-2.16.840.1.101.3.4.4.3_expandedkey_priv.der",
            output_relpath="corpus/appendix/public_repo/ossl35/ossl35_ml_kem_1024_expandedkey_priv.der",
            algorithm="ML-KEM",
            parameter_set="ML-KEM-1024",
            selection_reason="high-parameter pure ML-KEM expanded-key private key from ossl35 to extend hash-check and sizing coverage to the high end",
        ),
        _private_artifact(
            artifact_id="appendix-ossl35-mlkem1024-both-key",
            provider="ossl35",
            zip_relpath=zip_relpath,
            zip_member="ml-kem-1024-2.16.840.1.101.3.4.4.3_both_priv.der",
            output_relpath="corpus/appendix/public_repo/ossl35/ossl35_ml_kem_1024_both_priv.der",
            algorithm="ML-KEM",
            parameter_set="ML-KEM-1024",
            selection_reason="high-parameter pure ML-KEM both-form private key from ossl35 to combine consistency and hash-check coverage at the high end",
        ),
    ]


APPENDIX_ARTIFACTS: List[AppendixArtifact] = [
    AppendixArtifact(
        artifact_id="appendix-ossl35-mldsa44-ta-cert",
        provider="ossl35",
        zip_relpath="providers/ossl35/artifacts_certs_r5.zip",
        zip_member="ml-dsa-44-2.16.840.1.101.3.4.3.17_ta.der",
        output_relpath="corpus/appendix/public_repo/ossl35/ossl35_ml_dsa_44_ta.der",
        artifact_type="certificate",
        algorithm="ML-DSA",
        parameter_set="ML-DSA-44",
        stage="certificate/profile",
        selection_reason="final-R5 pure ML-DSA trust anchor from a widely used public implementation",
    ),
    AppendixArtifact(
        artifact_id="appendix-ossl35-mldsa65-ta-cert",
        provider="ossl35",
        zip_relpath="providers/ossl35/artifacts_certs_r5.zip",
        zip_member="ml-dsa-65-2.16.840.1.101.3.4.3.18_ta.der",
        output_relpath="corpus/appendix/public_repo/ossl35/ossl35_ml_dsa_65_ta.der",
        artifact_type="certificate",
        algorithm="ML-DSA",
        parameter_set="ML-DSA-65",
        stage="certificate/profile",
        selection_reason="final-R5 pure ML-DSA trust anchor from a widely used public implementation",
    ),
    AppendixArtifact(
        artifact_id="appendix-ossl35-mldsa87-ta-cert",
        provider="ossl35",
        zip_relpath="providers/ossl35/artifacts_certs_r5.zip",
        zip_member="ml-dsa-87-2.16.840.1.101.3.4.3.19_ta.der",
        output_relpath="corpus/appendix/public_repo/ossl35/ossl35_ml_dsa_87_ta.der",
        artifact_type="certificate",
        algorithm="ML-DSA",
        parameter_set="ML-DSA-87",
        stage="certificate/profile",
        selection_reason="final-R5 pure ML-DSA trust anchor from a widely used public implementation",
    ),
    AppendixArtifact(
        artifact_id="appendix-ossl35-mlkem512-ee-cert",
        provider="ossl35",
        zip_relpath="providers/ossl35/artifacts_certs_r5.zip",
        zip_member="ml-kem-512-2.16.840.1.101.3.4.4.1_ee.der",
        output_relpath="corpus/appendix/public_repo/ossl35/ossl35_ml_kem_512_ee.der",
        artifact_type="certificate",
        algorithm="ML-KEM",
        parameter_set="ML-KEM-512",
        stage="certificate/profile",
        selection_reason="final-R5 pure ML-KEM end-entity certificate covering the lowest NIST parameter set",
    ),
    AppendixArtifact(
        artifact_id="appendix-ossl35-mlkem768-ee-cert",
        provider="ossl35",
        zip_relpath="providers/ossl35/artifacts_certs_r5.zip",
        zip_member="ml-kem-768-2.16.840.1.101.3.4.4.2_ee.der",
        output_relpath="corpus/appendix/public_repo/ossl35/ossl35_ml_kem_768_ee.der",
        artifact_type="certificate",
        algorithm="ML-KEM",
        parameter_set="ML-KEM-768",
        stage="certificate/profile",
        selection_reason="final-R5 pure ML-KEM end-entity certificate covering the practical default security level",
    ),
    AppendixArtifact(
        artifact_id="appendix-ossl35-mlkem1024-ee-cert",
        provider="ossl35",
        zip_relpath="providers/ossl35/artifacts_certs_r5.zip",
        zip_member="ml-kem-1024-2.16.840.1.101.3.4.4.3_ee.der",
        output_relpath="corpus/appendix/public_repo/ossl35/ossl35_ml_kem_1024_ee.der",
        artifact_type="certificate",
        algorithm="ML-KEM",
        parameter_set="ML-KEM-1024",
        stage="certificate/profile",
        selection_reason="final-R5 pure ML-KEM end-entity certificate covering the highest NIST parameter set",
    ),
    AppendixArtifact(
        artifact_id="appendix-bc-mldsa65-ta-cert",
        provider="bc",
        zip_relpath="providers/bc/artifacts_certs_r5.zip",
        zip_member="artifacts/ml-dsa-65-2.16.840.1.101.3.4.3.18_ta.der",
        output_relpath="corpus/appendix/public_repo/bc/bc_ml_dsa_65_ta.der",
        artifact_type="certificate",
        algorithm="ML-DSA",
        parameter_set="ML-DSA-65",
        stage="certificate/profile",
        selection_reason="cross-provider pure ML-DSA certificate matching the private-key container variants selected for import-validation",
    ),
    AppendixArtifact(
        artifact_id="appendix-bc-mldsa65-seed-key",
        provider="bc",
        zip_relpath="providers/bc/artifacts_certs_r5.zip",
        zip_member="artifacts/ml-dsa-65-2.16.840.1.101.3.4.3.18_seed_priv.der",
        output_relpath="corpus/appendix/public_repo/bc/bc_ml_dsa_65_seed_priv.der",
        artifact_type="private-key-container",
        algorithm="ML-DSA",
        parameter_set="ML-DSA-65",
        stage="private-key-container/import",
        selection_reason="cross-provider seed-only ML-DSA private key for import-format external validity",
    ),
    AppendixArtifact(
        artifact_id="appendix-bc-mldsa65-expanded-key",
        provider="bc",
        zip_relpath="providers/bc/artifacts_certs_r5.zip",
        zip_member="artifacts/ml-dsa-65-2.16.840.1.101.3.4.3.18_expandedkey_priv.der",
        output_relpath="corpus/appendix/public_repo/bc/bc_ml_dsa_65_expandedkey_priv.der",
        artifact_type="private-key-container",
        algorithm="ML-DSA",
        parameter_set="ML-DSA-65",
        stage="private-key-container/import",
        selection_reason="cross-provider expanded-key ML-DSA private key for import-format external validity",
    ),
    AppendixArtifact(
        artifact_id="appendix-bc-mldsa65-both-key",
        provider="bc",
        zip_relpath="providers/bc/artifacts_certs_r5.zip",
        zip_member="artifacts/ml-dsa-65-2.16.840.1.101.3.4.3.18_both_priv.der",
        output_relpath="corpus/appendix/public_repo/bc/bc_ml_dsa_65_both_priv.der",
        artifact_type="private-key-container",
        algorithm="ML-DSA",
        parameter_set="ML-DSA-65",
        stage="private-key-container/import",
        selection_reason="cross-provider both-form ML-DSA private key exercising seed-expanded consistency parsing",
    ),
    AppendixArtifact(
        artifact_id="appendix-bc-mlkem768-ee-cert",
        provider="bc",
        zip_relpath="providers/bc/artifacts_certs_r5.zip",
        zip_member="artifacts/ml-kem-768-2.16.840.1.101.3.4.4.2_ee.der",
        output_relpath="corpus/appendix/public_repo/bc/bc_ml_kem_768_ee.der",
        artifact_type="certificate",
        algorithm="ML-KEM",
        parameter_set="ML-KEM-768",
        stage="certificate/profile",
        selection_reason="cross-provider pure ML-KEM certificate matching the private-key container variants selected for import-validation",
    ),
    AppendixArtifact(
        artifact_id="appendix-bc-mlkem768-seed-key",
        provider="bc",
        zip_relpath="providers/bc/artifacts_certs_r5.zip",
        zip_member="artifacts/ml-kem-768-2.16.840.1.101.3.4.4.2_seed_priv.der",
        output_relpath="corpus/appendix/public_repo/bc/bc_ml_kem_768_seed_priv.der",
        artifact_type="private-key-container",
        algorithm="ML-KEM",
        parameter_set="ML-KEM-768",
        stage="private-key-container/import",
        selection_reason="cross-provider seed-only ML-KEM private key for import-format external validity",
    ),
    AppendixArtifact(
        artifact_id="appendix-bc-mlkem768-expanded-key",
        provider="bc",
        zip_relpath="providers/bc/artifacts_certs_r5.zip",
        zip_member="artifacts/ml-kem-768-2.16.840.1.101.3.4.4.2_expandedkey_priv.der",
        output_relpath="corpus/appendix/public_repo/bc/bc_ml_kem_768_expandedkey_priv.der",
        artifact_type="private-key-container",
        algorithm="ML-KEM",
        parameter_set="ML-KEM-768",
        stage="private-key-container/import",
        selection_reason="cross-provider expanded-key ML-KEM private key exercising hash-check parsing on non-OpenSSL material",
    ),
    AppendixArtifact(
        artifact_id="appendix-bc-mlkem768-both-key",
        provider="bc",
        zip_relpath="providers/bc/artifacts_certs_r5.zip",
        zip_member="artifacts/ml-kem-768-2.16.840.1.101.3.4.4.2_both_priv.der",
        output_relpath="corpus/appendix/public_repo/bc/bc_ml_kem_768_both_priv.der",
        artifact_type="private-key-container",
        algorithm="ML-KEM",
        parameter_set="ML-KEM-768",
        stage="private-key-container/import",
        selection_reason="cross-provider both-form ML-KEM private key exercising seed-expanded consistency and hash-check parsing",
    ),
] + _ossl35_extremal_private_artifacts()


def repo_commit(repo_root: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
        capture_output=True,
        check=True,
        text=True,
    )
    return result.stdout.strip()


def zip_digest(root: Path, zip_relpath: str) -> str:
    return sha256(root / THIRD_PARTY_REPO / zip_relpath)


def extract_artifacts(root: Path) -> None:
    for artifact in APPENDIX_ARTIFACTS:
        zip_path = root / THIRD_PARTY_REPO / artifact.zip_relpath
        output_path = root / artifact.output_relpath
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(zip_path) as archive:
            data = archive.read(artifact.zip_member)
        output_path.write_bytes(data)


def build_manifest(root: Path, access_date: str) -> List[Dict[str, Any]]:
    repo_root = root / THIRD_PARTY_REPO
    commit = repo_commit(repo_root)
    zip_digests = {
        artifact.zip_relpath: zip_digest(root, artifact.zip_relpath)
        for artifact in APPENDIX_ARTIFACTS
    }
    records: List[Dict[str, Any]] = []
    for artifact in APPENDIX_ARTIFACTS:
        output_path = root / artifact.output_relpath
        if not output_path.exists():
            continue
        records.append(
            artifact.manifest_record(
                root=root,
                repo_commit=commit,
                access_date=access_date,
                zip_digest=zip_digests[artifact.zip_relpath],
            )
        )
    return records


def load_manifest(path: Path) -> List[Dict[str, Any]]:
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


def write_manifest(path: Path, records: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")


def write_ledger(path: Path, records: List[Dict[str, Any]], access_date: str, root: Path) -> None:
    repo_root = root / THIRD_PARTY_REPO
    commit = _manifest_locator(records, "commit:") or (
        repo_commit(repo_root) if repo_root.exists() else "frozen-manifest"
    )
    frozen_access_date = _manifest_locator(records, "access-date:") or access_date
    zip_entries = sorted(
        {
            (
                _record_locator(record, "zip:"),
                _record_locator(record, "zip-sha256:"),
            )
            for record in records
            if _record_locator(record, "zip:")
        }
    )
    lines = [
        "# Appendix Corpus Provenance",
        "",
        "This appendix records the bounded public corpus used to complement the",
        "controlled evaluation. It is a reproducible subset of public repository",
        "artifacts selected to add limited external-validity evidence within the",
        "scope of the paper.",
        "",
        "## Snapshot",
        "",
        f"- Source repository: {REPO_URL}",
        (
            f"- Local snapshot: `{THIRD_PARTY_REPO}`"
            if repo_root.exists()
            else "- Local snapshot: frozen manifest metadata only (no live pqc-certificates snapshot bundled)"
        ),
        f"- Commit: `{commit}`",
        f"- Access date frozen for this iteration: `{frozen_access_date}`",
        "- License locator: `third_party/pqc-certificates-main/license.txt`",
        "",
        "## Inclusion Rules",
        "",
        "- Include only final R5 public artifacts with final ML-KEM/ML-DSA OIDs.",
        "- Keep the appendix small enough to audit manually.",
        "- Prefer artifacts that exercise either full certificate/profile coverage or",
        "  private-key container import coverage across a second implementation.",
        "",
        "## Explicit Exclusions",
        "",
        "- `historical_artifacts/` draft-era material.",
        "- CMS/CMP payloads and ciphertext-based protocol artifacts.",
        "- Hybrid/composite/chameleon/catalyst certificates.",
        "- SLH-DSA families, which are outside the current paper scope.",
        "- HashML-DSA and hash-SLH-DSA families as executable appendix cases for now,",
        "  because the current core paper artifact is scoped to ML-KEM plus pure",
        "  ML-DSA, and the HashML-DSA prohibition remains a planned detector rather",
        "  than a closed experimental claim.",
        "",
        "## Source Archives",
        "",
    ]
    for zip_relpath, zip_sha in zip_entries:
        lines.append(f"- `{zip_relpath}` sha256 `{zip_sha}`")
    lines.extend(
        [
            "",
            "## Selected Artifacts",
            "",
        ]
    )
    for record in records:
        lines.extend(
            [
                f"- `{record['artifact_id']}`",
                f"  - provider: `{record['provider']}`",
                f"  - algorithm: `{record['algorithm']}` / `{record['parameter_set']}`",
                f"  - artifact type: `{record['artifact_type']}`",
                f"  - stage: `{record['stage']}`",
                f"  - extracted file: `{record['path']}`",
                f"  - file sha256: `{record['sha256']}`",
                f"  - selection reason: {record['selection_reason']}",
                f"  - source entry: `{record['source_locators'][4]}` / `{record['source_locators'][5]}`",
            ]
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_appendix_summary(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "status": "appendix-selection-upgraded",
        "artifact_count": len(records),
        "by_provider": dict(Counter(str(record.get("provider")) for record in records)),
        "by_artifact_type": dict(Counter(str(record.get("artifact_type")) for record in records)),
        "by_stage": dict(Counter(str(record.get("stage")) for record in records)),
        "by_algorithm": dict(Counter(str(record.get("algorithm")) for record in records)),
        "parameter_sets": sorted({str(record.get("parameter_set")) for record in records}),
        "selection_targets": {
            "provider_diversity": sorted({str(record.get("provider")) for record in records}),
            "artifact_surface_diversity": sorted(
                {str(record.get("artifact_type")) for record in records}
            ),
            "private_key_parameter_sets": sorted(
                {
                    str(record.get("parameter_set"))
                    for record in records
                    if record.get("artifact_type") == "private-key-container"
                }
            ),
        },
    }


def write_selection_rationale(path: Path, summary: Dict[str, Any]) -> None:
    lines = [
        "# Appendix Corpus Scope",
        "",
        "The public appendix is intentionally bounded. Its purpose is to add a small,",
        "reproducible external-validity layer to the controlled corpus without turning",
        "the repository into an ecosystem census.",
        "",
        "## Selection Priorities",
        "",
        "- Keep scope fixed to final ML-KEM and pure ML-DSA only.",
        "- Preserve two-provider evidence (`ossl35`, `bc`).",
        "- Strengthen importer-facing external validity with more private-key containers.",
        "- Cover low/default/high parameter sets across both algorithm families.",
        "- Keep the appendix small enough to audit manually and replay reliably.",
        "",
        "## Resulting Coverage",
        "",
        f"- artifact_count: {summary['artifact_count']}",
        f"- providers: {', '.join(summary['selection_targets']['provider_diversity'])}",
        f"- artifact surfaces: {', '.join(summary['selection_targets']['artifact_surface_diversity'])}",
        f"- parameter_sets: {', '.join(summary['parameter_sets'])}",
        (
            "- private-key parameter coverage: "
            f"{', '.join(summary['selection_targets']['private_key_parameter_sets'])}"
        ),
        "",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _record_locator(record: Dict[str, Any], prefix: str) -> str | None:
    for locator in record.get("source_locators", []):
        locator_text = str(locator)
        if locator_text.startswith(prefix):
            return locator_text[len(prefix) :]
    return None


def _manifest_locator(records: List[Dict[str, Any]], prefix: str) -> str | None:
    for record in records:
        value = _record_locator(record, prefix)
        if value is not None:
            return value
    return None


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "corpus" / "appendix" / "manifest.jsonl",
    )
    parser.add_argument(
        "--ledger",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "docs" / "real-world-appendix-ledger.md",
    )
    parser.add_argument(
        "--summary",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "results" / "appendix" / "appendix_coverage_summary.json",
    )
    parser.add_argument(
        "--selection-rationale",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "docs" / "appendix-selection-rationale.md",
    )
    parser.add_argument("--access-date", default="2026-04-15")
    parser.add_argument("--extract", action="store_true")
    args = parser.parse_args(argv)

    root = args.root.resolve()
    repo_root = root / THIRD_PARTY_REPO
    if args.extract:
        if not repo_root.exists():
            raise SystemExit(
                f"Missing frozen pqc-certificates snapshot at {repo_root}; cannot extract appendix artifacts."
            )
        extract_artifacts(root)
    if repo_root.exists():
        records = build_manifest(root, args.access_date)
        access_date = args.access_date
    else:
        records = load_manifest(args.manifest)
        if not records:
            raise SystemExit(
                "Frozen appendix manifest is missing; cannot regenerate appendix documentation without a live snapshot."
            )
        access_date = _manifest_locator(records, "access-date:") or args.access_date
    summary = build_appendix_summary(records)
    write_manifest(args.manifest, records)
    write_ledger(args.ledger, records, access_date, root)
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_selection_rationale(args.selection_rationale, summary)
    print(f"wrote {args.manifest}")
    print(f"wrote {args.ledger}")
    print(f"wrote {args.summary}")
    print(f"wrote {args.selection_rationale}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
