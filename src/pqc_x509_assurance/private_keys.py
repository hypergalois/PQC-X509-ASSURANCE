"""Narrow PKCS#8 / OneAsymmetricKey parsing for PQ private-key containers."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Dict, List, Optional

from .der import DERError, DERNode, oid, parse_der
from .import_validation import check_seed_expanded_consistency
from .x509 import AlgorithmIdentifier, MLDSA_OIDS, MLKEM_OIDS, parse_algorithm_identifier


MLKEM_PRIVATE_SEED_LENGTH = 64
MLKEM_PRIVATE_DKPKE_LENGTHS = {
    "ML-KEM-512": 768,
    "ML-KEM-768": 1152,
    "ML-KEM-1024": 1536,
}
MLKEM_PRIVATE_EXPANDED_LENGTHS = {
    "ML-KEM-512": 1632,
    "ML-KEM-768": 2400,
    "ML-KEM-1024": 3168,
}

MLDSA_PRIVATE_SEED_LENGTH = 32
MLDSA_PRIVATE_EXPANDED_LENGTHS = {
    "ML-DSA-44": 2560,
    "ML-DSA-65": 4032,
    "ML-DSA-87": 4896,
}


@dataclass(frozen=True)
class PrivateKeyView:
    algorithm: AlgorithmIdentifier
    parameter_set: str
    representation: str
    seed: Optional[bytes]
    expanded_key: Optional[bytes]


def parse_private_key_container(data: bytes) -> PrivateKeyView:
    root = parse_der(data)
    if root.tag != 0x30:
        raise DERError("PrivateKeyInfo is not a SEQUENCE")
    children = root.children()
    if len(children) < 3:
        raise DERError("PrivateKeyInfo must contain version, privateKeyAlgorithm, and privateKey")
    if children[0].tag != 0x02:
        raise DERError("PrivateKeyInfo version is not an INTEGER")
    algorithm = parse_algorithm_identifier(children[1])
    if children[2].tag != 0x04:
        raise DERError("PrivateKeyInfo privateKey field is not an OCTET STRING")

    parameter_set = _parameter_set_for_oid(algorithm.oid)
    representation, seed, expanded_key = _parse_private_key_payload(
        parse_der(children[2].value),
        parameter_set,
    )
    return PrivateKeyView(
        algorithm=algorithm,
        parameter_set=parameter_set,
        representation=representation,
        seed=seed,
        expanded_key=expanded_key,
    )


def lint_private_key_container_der(data: bytes) -> List[Dict[str, str]]:
    view = parse_private_key_container(data)
    findings: List[Dict[str, str]] = []
    if view.algorithm.oid in MLKEM_OIDS:
        seed_ok = False
        if view.seed is not None:
            seed_ok = _record_octets_length(
                findings,
                "MLKEM-PRIVATE-SEED-LENGTH",
                "detector.private_key.mlkem_seed_length",
                view.seed,
                MLKEM_PRIVATE_SEED_LENGTH,
                f"{view.parameter_set} private-key seed",
            )
        expanded_ok = False
        if view.expanded_key is not None:
            expanded_ok = _record_octets_length(
                findings,
                "MLKEM-PRIVATE-EXPANDED-LENGTH",
                "detector.private_key.mlkem_expanded_length",
                view.expanded_key,
                MLKEM_PRIVATE_EXPANDED_LENGTHS[view.parameter_set],
                f"{view.parameter_set} expanded private key",
            )
        if view.expanded_key is not None and expanded_ok:
            _record_mlkem_hash_check(findings, view.parameter_set, view.expanded_key)
        if view.seed is not None and view.expanded_key is not None and seed_ok and expanded_ok:
            _record_consistency_check(
                findings,
                requirement_id="MLKEM-PRIVATE-BOTH-CONSISTENCY",
                detector="detector.private_key.mlkem_seed_expanded_consistency",
                parameter_set=view.parameter_set,
                seed=view.seed,
                expanded_key=view.expanded_key,
                label=f"{view.parameter_set} seed/expanded private-key consistency",
            )
    elif view.algorithm.oid in MLDSA_OIDS:
        seed_ok = False
        if view.seed is not None:
            seed_ok = _record_octets_length(
                findings,
                "MLDSA-PRIVATE-SEED-LENGTH",
                "detector.private_key.mldsa_seed_length",
                view.seed,
                MLDSA_PRIVATE_SEED_LENGTH,
                f"{view.parameter_set} private-key seed",
            )
        expanded_ok = False
        if view.expanded_key is not None:
            expanded_ok = _record_octets_length(
                findings,
                "MLDSA-PRIVATE-EXPANDED-LENGTH",
                "detector.private_key.mldsa_expanded_length",
                view.expanded_key,
                MLDSA_PRIVATE_EXPANDED_LENGTHS[view.parameter_set],
                f"{view.parameter_set} expanded private key",
            )
        if view.seed is not None and view.expanded_key is not None and seed_ok and expanded_ok:
            _record_consistency_check(
                findings,
                requirement_id="MLDSA-PRIVATE-BOTH-CONSISTENCY",
                detector="detector.private_key.mldsa_seed_expanded_consistency",
                parameter_set=view.parameter_set,
                seed=view.seed,
                expanded_key=view.expanded_key,
                label=f"{view.parameter_set} seed/expanded private-key consistency",
            )
    return findings


def _parameter_set_for_oid(algorithm_oid: str) -> str:
    parameter_set = MLKEM_OIDS.get(algorithm_oid) or MLDSA_OIDS.get(algorithm_oid)
    if parameter_set is None:
        raise DERError(f"unsupported PQ private-key algorithm OID: {algorithm_oid}")
    return parameter_set


def _parse_private_key_payload(node: DERNode, parameter_set: str) -> tuple[str, Optional[bytes], Optional[bytes]]:
    if node.tag == 0x30:
        children = node.children()
        if len(children) != 2:
            raise DERError("PQC both-key private-key form must contain exactly two children")
        seed = _node_octets(children[0], "seed")
        expanded = _node_octets(children[1], "expandedKey")
        return "both", seed, expanded

    if node.tag in {0x04, 0x80, 0x81, 0xA0, 0xA1}:
        payload = _node_octets(node, "private key")
        seed_length, expanded_length = _expected_lengths(parameter_set)
        if len(payload) == seed_length:
            return "seed", payload, None
        if len(payload) == expanded_length:
            return "expanded", None, payload
        raise DERError(
            "single private-key value length does not match the expected seed or expanded-key length"
        )

    if node.tag == 0xA2:
        explicit_children = node.children()
        if len(explicit_children) != 1:
            raise DERError("explicit [2] private-key wrapper must contain exactly one child")
        return _parse_private_key_payload(explicit_children[0], parameter_set)

    raise DERError(f"unsupported PQ private-key representation tag 0x{node.tag:02x}")


def _expected_lengths(parameter_set: str) -> tuple[int, int]:
    if parameter_set in MLKEM_PRIVATE_EXPANDED_LENGTHS:
        return MLKEM_PRIVATE_SEED_LENGTH, MLKEM_PRIVATE_EXPANDED_LENGTHS[parameter_set]
    if parameter_set in MLDSA_PRIVATE_EXPANDED_LENGTHS:
        return MLDSA_PRIVATE_SEED_LENGTH, MLDSA_PRIVATE_EXPANDED_LENGTHS[parameter_set]
    raise DERError(f"unsupported PQ parameter set: {parameter_set}")


def _node_octets(node: DERNode, label: str) -> bytes:
    if node.tag in {0x04, 0x80, 0x81}:
        return node.value
    if node.tag in {0xA0, 0xA1}:
        explicit_children = node.children()
        if len(explicit_children) != 1 or explicit_children[0].tag != 0x04:
            raise DERError(f"explicit {label} wrapper must contain exactly one OCTET STRING")
        return explicit_children[0].value
    raise DERError(f"{label} is not encoded as an OCTET STRING-compatible node")


def _record_octets_length(
    findings: List[Dict[str, str]],
    requirement_id: str,
    detector: str,
    payload: bytes,
    expected_length: int,
    label: str,
) -> bool:
    actual = len(payload)
    ok = actual == expected_length
    findings.append(
        {
            "detector": detector,
            "requirement_id": requirement_id,
            "status": "pass" if ok else "error",
            "message": f"{label} length is {actual}, expected {expected_length}",
        }
    )
    return ok


def _record_consistency_check(
    findings: List[Dict[str, str]],
    requirement_id: str,
    detector: str,
    parameter_set: str,
    seed: bytes,
    expanded_key: bytes,
    label: str,
) -> None:
    match, detail = check_seed_expanded_consistency(parameter_set, seed, expanded_key)
    findings.append(
        {
            "detector": detector,
            "requirement_id": requirement_id,
            "status": "pass" if match else "error",
            "message": f"{label}: {detail}",
        }
    )


def _record_mlkem_hash_check(
    findings: List[Dict[str, str]],
    parameter_set: str,
    expanded_key: bytes,
) -> None:
    dkpke_length = MLKEM_PRIVATE_DKPKE_LENGTHS[parameter_set]
    ek_length = MLKEM_PRIVATE_EXPANDED_LENGTHS[parameter_set] - dkpke_length - 64
    ek = expanded_key[dkpke_length : dkpke_length + ek_length]
    stored_hash = expanded_key[dkpke_length + ek_length : dkpke_length + ek_length + 32]
    computed_hash = hashlib.sha3_256(ek).digest()
    findings.append(
        {
            "detector": "detector.private_key.mlkem_hash_check",
            "requirement_id": "MLKEM-PRIVATE-EXPANDED-HASH-CHECK",
            "status": "pass" if stored_hash == computed_hash else "error",
            "message": (
                f"{parameter_set} expanded private key stored H(ek) "
                f"{'matches' if stored_hash == computed_hash else 'does not match'} computed SHA3-256"
            ),
        }
    )
