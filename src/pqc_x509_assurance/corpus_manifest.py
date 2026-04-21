"""Build corpus/manifest.jsonl for known generated corpus layouts."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List

from .der_mutations import DER_MUTATION_SPECS


OPENSSL_ARTIFACTS: List[Dict[str, Any]] = [
    {
        "artifact_id": "openssl-mldsa65-ca-cert",
        "filename": "openssl_mldsa65_ca_cert.pem",
        "artifact_type": "certificate",
        "algorithm": "ML-DSA",
        "parameter_set": "ML-DSA-65",
        "stage": "certificate/profile",
    },
    {
        "artifact_id": "openssl-mldsa44-ee-cert",
        "filename": "openssl_mldsa44_ee_cert.pem",
        "artifact_type": "certificate",
        "algorithm": "ML-DSA",
        "parameter_set": "ML-DSA-44",
        "stage": "certificate/profile",
    },
    {
        "artifact_id": "openssl-mldsa65-ee-cert",
        "filename": "openssl_mldsa65_ee_cert.pem",
        "artifact_type": "certificate",
        "algorithm": "ML-DSA",
        "parameter_set": "ML-DSA-65",
        "stage": "certificate/profile",
    },
    {
        "artifact_id": "openssl-mldsa87-ee-cert",
        "filename": "openssl_mldsa87_ee_cert.pem",
        "artifact_type": "certificate",
        "algorithm": "ML-DSA",
        "parameter_set": "ML-DSA-87",
        "stage": "certificate/profile",
    },
    {
        "artifact_id": "openssl-mlkem512-ee-cert",
        "filename": "openssl_mlkem512_ee_cert.pem",
        "artifact_type": "certificate",
        "algorithm": "ML-KEM",
        "parameter_set": "ML-KEM-512",
        "stage": "certificate/profile",
    },
    {
        "artifact_id": "openssl-mlkem768-ee-cert",
        "filename": "openssl_mlkem768_ee_cert.pem",
        "artifact_type": "certificate",
        "algorithm": "ML-KEM",
        "parameter_set": "ML-KEM-768",
        "stage": "certificate/profile",
    },
    {
        "artifact_id": "openssl-mlkem1024-ee-cert",
        "filename": "openssl_mlkem1024_ee_cert.pem",
        "artifact_type": "certificate",
        "algorithm": "ML-KEM",
        "parameter_set": "ML-KEM-1024",
        "stage": "certificate/profile",
    },
    {
        "artifact_id": "openssl-mldsa65-ca-key",
        "filename": "openssl_mldsa65_ca_key.pem",
        "artifact_type": "private-key-container",
        "algorithm": "ML-DSA",
        "parameter_set": "ML-DSA-65",
        "stage": "private-key-container/import",
    },
    {
        "artifact_id": "openssl-mldsa65-ca-pub",
        "filename": "openssl_mldsa65_ca_pub.pem",
        "artifact_type": "spki",
        "algorithm": "ML-DSA",
        "parameter_set": "ML-DSA-65",
        "stage": "SPKI/public-key",
    },
    {
        "artifact_id": "openssl-mldsa44-ee-key",
        "filename": "openssl_mldsa44_ee_key.pem",
        "artifact_type": "private-key-container",
        "algorithm": "ML-DSA",
        "parameter_set": "ML-DSA-44",
        "stage": "private-key-container/import",
    },
    {
        "artifact_id": "openssl-mldsa44-ee-pub",
        "filename": "openssl_mldsa44_ee_pub.pem",
        "artifact_type": "spki",
        "algorithm": "ML-DSA",
        "parameter_set": "ML-DSA-44",
        "stage": "SPKI/public-key",
    },
    {
        "artifact_id": "openssl-mldsa65-ee-key",
        "filename": "openssl_mldsa65_ee_key.pem",
        "artifact_type": "private-key-container",
        "algorithm": "ML-DSA",
        "parameter_set": "ML-DSA-65",
        "stage": "private-key-container/import",
    },
    {
        "artifact_id": "openssl-mldsa65-ee-pub",
        "filename": "openssl_mldsa65_ee_pub.pem",
        "artifact_type": "spki",
        "algorithm": "ML-DSA",
        "parameter_set": "ML-DSA-65",
        "stage": "SPKI/public-key",
    },
    {
        "artifact_id": "openssl-mldsa87-ee-key",
        "filename": "openssl_mldsa87_ee_key.pem",
        "artifact_type": "private-key-container",
        "algorithm": "ML-DSA",
        "parameter_set": "ML-DSA-87",
        "stage": "private-key-container/import",
    },
    {
        "artifact_id": "openssl-mldsa87-ee-pub",
        "filename": "openssl_mldsa87_ee_pub.pem",
        "artifact_type": "spki",
        "algorithm": "ML-DSA",
        "parameter_set": "ML-DSA-87",
        "stage": "SPKI/public-key",
    },
    {
        "artifact_id": "openssl-mlkem512-ee-key",
        "filename": "openssl_mlkem512_ee_key.pem",
        "artifact_type": "private-key-container",
        "algorithm": "ML-KEM",
        "parameter_set": "ML-KEM-512",
        "stage": "private-key-container/import",
    },
    {
        "artifact_id": "openssl-mlkem512-ee-pub",
        "filename": "openssl_mlkem512_ee_pub.pem",
        "artifact_type": "spki",
        "algorithm": "ML-KEM",
        "parameter_set": "ML-KEM-512",
        "stage": "SPKI/public-key",
    },
    {
        "artifact_id": "openssl-mlkem768-ee-key",
        "filename": "openssl_mlkem768_ee_key.pem",
        "artifact_type": "private-key-container",
        "algorithm": "ML-KEM",
        "parameter_set": "ML-KEM-768",
        "stage": "private-key-container/import",
    },
    {
        "artifact_id": "openssl-mlkem768-ee-pub",
        "filename": "openssl_mlkem768_ee_pub.pem",
        "artifact_type": "spki",
        "algorithm": "ML-KEM",
        "parameter_set": "ML-KEM-768",
        "stage": "SPKI/public-key",
    },
    {
        "artifact_id": "openssl-mlkem1024-ee-key",
        "filename": "openssl_mlkem1024_ee_key.pem",
        "artifact_type": "private-key-container",
        "algorithm": "ML-KEM",
        "parameter_set": "ML-KEM-1024",
        "stage": "private-key-container/import",
    },
    {
        "artifact_id": "openssl-mlkem1024-ee-pub",
        "filename": "openssl_mlkem1024_ee_pub.pem",
        "artifact_type": "spki",
        "algorithm": "ML-KEM",
        "parameter_set": "ML-KEM-1024",
        "stage": "SPKI/public-key",
    },
]

OPENSSL_MUTATED_ARTIFACTS: List[Dict[str, Any]] = [
    {
        "artifact_id": "openssl-mut-mlkem768-keyusage-digital-signature-cert",
        "filename": "openssl_mut_mlkem768_keyusage_digital_signature_cert.pem",
        "artifact_type": "certificate",
        "algorithm": "ML-KEM",
        "parameter_set": "ML-KEM-768",
        "stage": "certificate/profile",
        "validity": "invalid",
        "fault_family": "profile/usage-policy",
        "mutation": "ML-KEM certificate keyUsage uses digitalSignature instead of only keyEncipherment.",
        "mutation_family": [
            "keyusage-missing-key-encipherment",
            "keyusage-extra-prohibited-bit",
        ],
        "expected_detection": ["MLKEM-CERT-KU-KEYENCIPHERMENT-ONLY"],
    },
    {
        "artifact_id": "openssl-mut-mldsa65-keyusage-key-encipherment-cert",
        "filename": "openssl_mut_mldsa65_keyusage_key_encipherment_cert.pem",
        "artifact_type": "certificate",
        "algorithm": "ML-DSA",
        "parameter_set": "ML-DSA-65",
        "stage": "certificate/profile",
        "validity": "invalid",
        "fault_family": "profile/usage-policy",
        "mutation": "ML-DSA certificate keyUsage uses keyEncipherment and no signature-related bit.",
        "mutation_family": [
            "keyusage-missing-signature-bit",
            "keyusage-key-encipherment",
        ],
        "expected_detection": [
            "MLDSA-CERT-KU-AT-LEAST-ONE-SIGNING-BIT",
            "MLDSA-CERT-KU-NO-ENCIPHERMENT-OR-AGREEMENT"
        ],
    },
]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(root: Path) -> List[Dict[str, Any]]:
    valid_dir = root / "corpus" / "valid" / "openssl"
    mutated_dir = root / "corpus" / "mutated" / "openssl"
    records: List[Dict[str, Any]] = []
    for artifact in OPENSSL_ARTIFACTS:
        path = valid_dir / str(artifact["filename"])
        if not path.exists():
            continue
        record = {
            key: value
            for key, value in artifact.items()
            if key not in {"filename"}
        }
        record.update(
            {
                "path": str(path.relative_to(root)),
                "source": "OpenSSL local generation via experiments/generate_corpus_openssl.sh",
                "validity": "valid",
                "fault_family": "none",
                "mutation": "none",
                "mutation_family": [],
                "expected_detection": [],
                "sha256": sha256(path),
            }
        )
        records.append(record)
    for artifact in OPENSSL_MUTATED_ARTIFACTS:
        path = mutated_dir / str(artifact["filename"])
        if not path.exists():
            continue
        record = {
            key: value
            for key, value in artifact.items()
            if key not in {"filename"}
        }
        record.update(
            {
                "path": str(path.relative_to(root)),
                "source": "OpenSSL local mutation via experiments/generate_mutations_openssl.sh",
                "sha256": sha256(path),
            }
        )
        records.append(record)
    for artifact in DER_MUTATION_SPECS:
        path = root / artifact.output_path
        if not path.exists():
            continue
        record = artifact.manifest_record()
        record.update(
            {
                "path": str(path.relative_to(root)),
                "source": "Deterministic DER mutation via experiments/generate_der_mutations.sh",
                "sha256": sha256(path),
            }
        )
        records.append(record)
    return records


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()

    root = args.root.resolve()
    out = args.out or root / "corpus" / "manifest.jsonl"
    records = build_manifest(root)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
    print(f"wrote {out} with {len(records)} records")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
