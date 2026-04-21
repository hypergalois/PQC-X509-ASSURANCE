"""
Detector inventory for the extended assurance suite.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable


@dataclass(frozen=True)
class Detector:
    name: str
    stage: str
    status: str
    note: str


DETECTORS: Dict[str, Detector] = {
    "detector.algorithm_identifier.parameters_absent": Detector(
        name="detector.algorithm_identifier.parameters_absent",
        stage="certificate/profile",
        status="implemented",
        note="DER AlgorithmIdentifier OID plus absent parameters check.",
    ),
    "detector.key_usage.mlkem_key_encipherment_only": Detector(
        name="detector.key_usage.mlkem_key_encipherment_only",
        stage="certificate/profile",
        status="implemented",
        note="ML-KEM keyUsage positive and negative check.",
    ),
    "detector.key_usage.mldsa_requires_signing_usage": Detector(
        name="detector.key_usage.mldsa_requires_signing_usage",
        stage="certificate/profile",
        status="implemented",
        note="ML-DSA keyUsage positive signing-bit check.",
    ),
    "detector.key_usage.mldsa_forbid_encipherment_agreement": Detector(
        name="detector.key_usage.mldsa_forbid_encipherment_agreement",
        stage="certificate/profile",
        status="implemented",
        note="Baseline rejects prohibited ML-DSA keyUsage bits; still needs corpus verification.",
    ),
    "detector.signature_algorithm.mldsa_parameters_absent": Detector(
        name="detector.signature_algorithm.mldsa_parameters_absent",
        stage="certificate/profile",
        status="implemented",
        note="ML-DSA signatureAlgorithm OID plus absent parameters check.",
    ),
    "detector.spki.payload_length": Detector(
        name="detector.spki.payload_length",
        stage="SPKI/public-key",
        status="implemented",
        note="OID-specific BIT STRING payload length check.",
    ),
    "detector.mlkem.encode_decode_identity": Detector(
        name="detector.mlkem.encode_decode_identity",
        stage="SPKI/public-key",
        status="implemented",
        note="Local canonical ByteDecode12/ByteEncode12 identity check for ML-KEM encapsulation keys.",
    ),
    "detector.algorithm_policy.hashml_dsa_forbidden": Detector(
        name="detector.algorithm_policy.hashml_dsa_forbidden",
        stage="certificate/profile",
        status="implemented",
        note="Reject HashML-DSA signature identifiers in prohibited PKIX certificate contexts.",
    ),
    "detector.private_key.mlkem_seed_length": Detector(
        name="detector.private_key.mlkem_seed_length",
        stage="private-key-container/import",
        status="implemented",
        note="OneAsymmetricKey ML-KEM seed length check.",
    ),
    "detector.private_key.mlkem_expanded_length": Detector(
        name="detector.private_key.mlkem_expanded_length",
        stage="private-key-container/import",
        status="implemented",
        note="OneAsymmetricKey ML-KEM expanded private-key length check.",
    ),
    "detector.private_key.mlkem_seed_expanded_consistency": Detector(
        name="detector.private_key.mlkem_seed_expanded_consistency",
        stage="private-key-container/import",
        status="implemented",
        note="Seed/expanded consistency check backed by the local libcrux import-validation bridge.",
    ),
    "detector.private_key.mlkem_hash_check": Detector(
        name="detector.private_key.mlkem_hash_check",
        stage="private-key-container/import",
        status="implemented",
        note="Expanded private-key H(ek) check implemented locally from the FIPS/RFC layout.",
    ),
    "detector.private_key.mldsa_seed_length": Detector(
        name="detector.private_key.mldsa_seed_length",
        stage="private-key-container/import",
        status="implemented",
        note="OneAsymmetricKey ML-DSA seed length check.",
    ),
    "detector.private_key.mldsa_expanded_length": Detector(
        name="detector.private_key.mldsa_expanded_length",
        stage="private-key-container/import",
        status="implemented",
        note="OneAsymmetricKey ML-DSA expanded private-key length check.",
    ),
    "detector.private_key.mldsa_seed_expanded_consistency": Detector(
        name="detector.private_key.mldsa_seed_expanded_consistency",
        stage="private-key-container/import",
        status="implemented",
        note="Seed/expanded consistency check backed by the local libcrux import-validation bridge.",
    ),
}


def all_detectors() -> Iterable[Detector]:
    return DETECTORS.values()


def detector_status(name: str) -> str:
    detector = DETECTORS.get(name)
    if detector is None:
        return "missing-detector-metadata"
    return detector.status
