"""
Deterministic DER mutations for the PQ X.509 corpus.

Every operation targets one supported
structure and re-encodes enclosing DER lengths instead of doing blind byte
replacement. That keeps the mutated artifacts parseable while isolating the
intended normative violation.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from .der import DERError, DERNode, bit_string_payload, oid, parse_der
from .x509 import _tbs_index_after_version


NULL_DER = b"\x05\x00"
OCTET_ZERO_DER = b"\x04\x01\x00"
OID_KEY_USAGE = "2.5.29.15"


@dataclass(frozen=True)
class DerMutationSpec:
    artifact_id: str
    source_path: str
    output_path: str
    artifact_type: str
    algorithm: str
    parameter_set: str
    stage: str
    fault_family: str
    mutation: str
    expected_detection: Tuple[str, ...]
    mutation_family: Tuple[str, ...]
    operation: str
    args: Dict[str, Any] = field(default_factory=dict)

    def manifest_record(self) -> Dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "artifact_type": self.artifact_type,
            "algorithm": self.algorithm,
            "parameter_set": self.parameter_set,
            "stage": self.stage,
            "validity": "invalid",
            "fault_family": self.fault_family,
            "mutation": self.mutation,
            "expected_detection": list(self.expected_detection),
            "mutation_family": list(self.mutation_family),
        }


DER_MUTATION_SPECS: List[DerMutationSpec] = [
    DerMutationSpec(
        artifact_id="der-mut-mlkem768-spki-aid-null-pub",
        source_path="corpus/valid/openssl/openssl_mlkem768_ee_pub.pem",
        output_path="corpus/mutated/der/der_mut_mlkem768_spki_aid_null_pub.pem",
        artifact_type="spki",
        algorithm="ML-KEM",
        parameter_set="ML-KEM-768",
        stage="SPKI/public-key",
        fault_family="encoding/container",
        mutation="Insert DER NULL parameters into ML-KEM SPKI AlgorithmIdentifier.",
        expected_detection=("MLKEM-SPKI-AID-PARAMS-ABSENT",),
        mutation_family=("aid-parameters-null",),
        operation="spki_add_null_params",
    ),
    DerMutationSpec(
        artifact_id="der-mut-mlkem768-spki-aid-octet-params-pub",
        source_path="corpus/valid/openssl/openssl_mlkem768_ee_pub.pem",
        output_path="corpus/mutated/der/der_mut_mlkem768_spki_aid_octet_params_pub.pem",
        artifact_type="spki",
        algorithm="ML-KEM",
        parameter_set="ML-KEM-768",
        stage="SPKI/public-key",
        fault_family="encoding/container",
        mutation="Insert non-NULL OCTET STRING parameters into ML-KEM SPKI AlgorithmIdentifier.",
        expected_detection=("MLKEM-SPKI-AID-PARAMS-ABSENT",),
        mutation_family=("aid-parameters-present-non-null",),
        operation="spki_add_octet_params",
    ),
    DerMutationSpec(
        artifact_id="der-mut-mldsa65-spki-aid-null-pub",
        source_path="corpus/valid/openssl/openssl_mldsa65_ee_pub.pem",
        output_path="corpus/mutated/der/der_mut_mldsa65_spki_aid_null_pub.pem",
        artifact_type="spki",
        algorithm="ML-DSA",
        parameter_set="ML-DSA-65",
        stage="SPKI/public-key",
        fault_family="encoding/container",
        mutation="Insert DER NULL parameters into ML-DSA SPKI AlgorithmIdentifier.",
        expected_detection=("MLDSA-SPKI-AID-PARAMS-ABSENT",),
        mutation_family=("aid-parameters-null",),
        operation="spki_add_null_params",
    ),
    DerMutationSpec(
        artifact_id="der-mut-mldsa65-spki-aid-octet-params-pub",
        source_path="corpus/valid/openssl/openssl_mldsa65_ee_pub.pem",
        output_path="corpus/mutated/der/der_mut_mldsa65_spki_aid_octet_params_pub.pem",
        artifact_type="spki",
        algorithm="ML-DSA",
        parameter_set="ML-DSA-65",
        stage="SPKI/public-key",
        fault_family="encoding/container",
        mutation="Insert non-NULL OCTET STRING parameters into ML-DSA SPKI AlgorithmIdentifier.",
        expected_detection=("MLDSA-SPKI-AID-PARAMS-ABSENT",),
        mutation_family=("aid-parameters-present-non-null",),
        operation="spki_add_octet_params",
    ),
    DerMutationSpec(
        artifact_id="der-mut-mlkem768-spki-payload-truncated-pub",
        source_path="corpus/valid/openssl/openssl_mlkem768_ee_pub.pem",
        output_path="corpus/mutated/der/der_mut_mlkem768_spki_payload_truncated_pub.pem",
        artifact_type="spki",
        algorithm="ML-KEM",
        parameter_set="ML-KEM-768",
        stage="SPKI/public-key",
        fault_family="size/shape",
        mutation="Truncate ML-KEM-768 SPKI BIT STRING payload by one byte.",
        expected_detection=("MLKEM-SPKI-PUBLIC-KEY-LENGTH",),
        mutation_family=("spki-public-key-truncate",),
        operation="spki_payload_delta",
        args={"delta": -1},
    ),
    DerMutationSpec(
        artifact_id="der-mut-mldsa87-spki-payload-2602-pub",
        source_path="corpus/valid/openssl/openssl_mldsa87_ee_pub.pem",
        output_path="corpus/mutated/der/der_mut_mldsa87_spki_payload_2602_pub.pem",
        artifact_type="spki",
        algorithm="ML-DSA",
        parameter_set="ML-DSA-87",
        stage="SPKI/public-key",
        fault_family="size/shape",
        mutation="Extend ML-DSA-87 SPKI payload to 2602 bytes to exercise the RFC 9881 appendix transcription conflict.",
        expected_detection=("MLDSA-SPKI-PUBLIC-KEY-LENGTH",),
        mutation_family=("spki-public-key-extend", "rfc9881-appendix-size-transcription-2602"),
        operation="spki_payload_target_length",
        args={"length": 2602},
    ),
    DerMutationSpec(
        artifact_id="der-mut-mlkem512-spki-oid-swapped-to-mlkem768-pub",
        source_path="corpus/valid/openssl/openssl_mlkem512_ee_pub.pem",
        output_path="corpus/mutated/der/der_mut_mlkem512_spki_oid_swapped_to_mlkem768_pub.pem",
        artifact_type="spki",
        algorithm="ML-KEM",
        parameter_set="ML-KEM-768 OID with ML-KEM-512 payload",
        stage="SPKI/public-key",
        fault_family="inter-field-consistency",
        mutation="Replace the ML-KEM-512 SPKI OID with ML-KEM-768 while leaving the ML-KEM-512 payload unchanged.",
        expected_detection=("MLKEM-SPKI-PUBLIC-KEY-LENGTH",),
        mutation_family=("spki-oid-length-mismatch",),
        operation="spki_replace_oid",
        args={"oid": "2.16.840.1.101.3.4.4.2"},
    ),
    DerMutationSpec(
        artifact_id="der-mut-mldsa44-spki-oid-swapped-to-mldsa65-pub",
        source_path="corpus/valid/openssl/openssl_mldsa44_ee_pub.pem",
        output_path="corpus/mutated/der/der_mut_mldsa44_spki_oid_swapped_to_mldsa65_pub.pem",
        artifact_type="spki",
        algorithm="ML-DSA",
        parameter_set="ML-DSA-65 OID with ML-DSA-44 payload",
        stage="SPKI/public-key",
        fault_family="inter-field-consistency",
        mutation="Replace the ML-DSA-44 SPKI OID with ML-DSA-65 while leaving the ML-DSA-44 payload unchanged.",
        expected_detection=("MLDSA-SPKI-PUBLIC-KEY-LENGTH",),
        mutation_family=("spki-oid-length-mismatch",),
        operation="spki_replace_oid",
        args={"oid": "2.16.840.1.101.3.4.3.18"},
    ),
    DerMutationSpec(
        artifact_id="der-mut-mldsa65-spki-oid-swapped-to-mlkem768-pub",
        source_path="corpus/valid/openssl/openssl_mldsa65_ee_pub.pem",
        output_path="corpus/mutated/der/der_mut_mldsa65_spki_oid_swapped_to_mlkem768_pub.pem",
        artifact_type="spki",
        algorithm="ML-KEM",
        parameter_set="ML-KEM-768 with ML-DSA-65 payload",
        stage="SPKI/public-key",
        fault_family="inter-field-consistency",
        mutation="Replace the ML-DSA-65 SPKI OID with ML-KEM-768 while leaving the ML-DSA payload unchanged.",
        expected_detection=("MLKEM-SPKI-PUBLIC-KEY-LENGTH",),
        mutation_family=("aid-oid-family-swap", "spki-oid-length-mismatch"),
        operation="spki_replace_oid",
        args={"oid": "2.16.840.1.101.3.4.4.2"},
    ),
    DerMutationSpec(
        artifact_id="der-mut-mlkem768-spki-unreduced-byteencode12-pub",
        source_path="corpus/valid/openssl/openssl_mlkem768_ee_pub.pem",
        output_path="corpus/mutated/der/der_mut_mlkem768_spki_unreduced_byteencode12_pub.pem",
        artifact_type="spki",
        algorithm="ML-KEM",
        parameter_set="ML-KEM-768",
        stage="SPKI/public-key",
        fault_family="field-domain",
        mutation="Replace the first ML-KEM-768 ByteEncode12 coefficient with an unreduced 12-bit value while preserving payload length.",
        expected_detection=("MLKEM-SPKI-ENCODE-DECODE-IDENTITY",),
        mutation_family=("mlkem-unreduced-byteencode12-value",),
        operation="spki_mlkem_unreduced_value",
        args={"value": 4095, "coefficient_index": 0},
    ),
    DerMutationSpec(
        artifact_id="der-mut-mlkem768-cert-spki-aid-null",
        source_path="corpus/valid/openssl/openssl_mlkem768_ee_cert.pem",
        output_path="corpus/mutated/der/der_mut_mlkem768_cert_spki_aid_null.pem",
        artifact_type="certificate",
        algorithm="ML-KEM",
        parameter_set="ML-KEM-768",
        stage="SPKI/public-key",
        fault_family="encoding/container",
        mutation="Insert DER NULL parameters into the certificate SPKI AlgorithmIdentifier.",
        expected_detection=("MLKEM-SPKI-AID-PARAMS-ABSENT",),
        mutation_family=("aid-parameters-null",),
        operation="certificate_spki_add_null_params",
    ),
    DerMutationSpec(
        artifact_id="der-mut-mlkem768-cert-spki-aid-octet-params",
        source_path="corpus/valid/openssl/openssl_mlkem768_ee_cert.pem",
        output_path="corpus/mutated/der/der_mut_mlkem768_cert_spki_aid_octet_params.pem",
        artifact_type="certificate",
        algorithm="ML-KEM",
        parameter_set="ML-KEM-768",
        stage="SPKI/public-key",
        fault_family="encoding/container",
        mutation="Insert non-NULL OCTET STRING parameters into the certificate SPKI AlgorithmIdentifier.",
        expected_detection=("MLKEM-SPKI-AID-PARAMS-ABSENT",),
        mutation_family=("aid-parameters-present-non-null",),
        operation="certificate_spki_add_octet_params",
    ),
    DerMutationSpec(
        artifact_id="der-mut-mlkem768-cert-spki-payload-truncated",
        source_path="corpus/valid/openssl/openssl_mlkem768_ee_cert.pem",
        output_path="corpus/mutated/der/der_mut_mlkem768_cert_spki_payload_truncated.pem",
        artifact_type="certificate",
        algorithm="ML-KEM",
        parameter_set="ML-KEM-768",
        stage="SPKI/public-key",
        fault_family="size/shape",
        mutation="Truncate the certificate ML-KEM-768 SPKI BIT STRING payload by one byte.",
        expected_detection=("MLKEM-SPKI-PUBLIC-KEY-LENGTH",),
        mutation_family=("spki-public-key-truncate",),
        operation="certificate_spki_payload_delta",
        args={"delta": -1},
    ),
    DerMutationSpec(
        artifact_id="der-mut-mldsa44-cert-signature-aid-null",
        source_path="corpus/valid/openssl/openssl_mldsa44_ee_cert.pem",
        output_path="corpus/mutated/der/der_mut_mldsa44_cert_signature_aid_null.pem",
        artifact_type="certificate",
        algorithm="ML-DSA",
        parameter_set="ML-DSA-44",
        stage="certificate/profile",
        fault_family="encoding/container",
        mutation="Insert DER NULL parameters into both ML-DSA certificate signature AlgorithmIdentifiers.",
        expected_detection=("MLDSA-CERT-SIGNATURE-AID-PARAMS-ABSENT",),
        mutation_family=("signature-aid-parameters-null",),
        operation="certificate_signature_add_null_params",
    ),
    DerMutationSpec(
        artifact_id="der-mut-mldsa44-cert-signature-aid-octet-params",
        source_path="corpus/valid/openssl/openssl_mldsa44_ee_cert.pem",
        output_path="corpus/mutated/der/der_mut_mldsa44_cert_signature_aid_octet_params.pem",
        artifact_type="certificate",
        algorithm="ML-DSA",
        parameter_set="ML-DSA-44",
        stage="certificate/profile",
        fault_family="encoding/container",
        mutation="Insert non-NULL OCTET STRING parameters into both ML-DSA certificate signature AlgorithmIdentifiers.",
        expected_detection=("MLDSA-CERT-SIGNATURE-AID-PARAMS-ABSENT",),
        mutation_family=("signature-aid-parameters-present-non-null",),
        operation="certificate_signature_add_octet_params",
    ),
    DerMutationSpec(
        artifact_id="der-mut-mldsa44-cert-signature-hashmldsa44",
        source_path="corpus/valid/openssl/openssl_mldsa44_ee_cert.pem",
        output_path="corpus/mutated/der/der_mut_mldsa44_cert_signature_hashmldsa44.pem",
        artifact_type="certificate",
        algorithm="ML-DSA",
        parameter_set="HashML-DSA-44 in PKIX certificate context",
        stage="certificate/profile",
        fault_family="algorithm-policy",
        mutation="Replace both certificate ML-DSA-44 signature AlgorithmIdentifiers with HashML-DSA-44.",
        expected_detection=("MLDSA-PKIX-HASHML-FORBIDDEN",),
        mutation_family=("hashml-dsa-signature-oid-in-pkix-cert", "hashml-dsa-pkix-context"),
        operation="certificate_signature_replace_oid",
        args={"oid": "2.16.840.1.101.3.4.3.32"},
    ),
    DerMutationSpec(
        artifact_id="der-mut-mlkem768-cert-keyusage-empty",
        source_path="corpus/valid/openssl/openssl_mlkem768_ee_cert.pem",
        output_path="corpus/mutated/der/der_mut_mlkem768_cert_keyusage_empty.pem",
        artifact_type="certificate",
        algorithm="ML-KEM",
        parameter_set="ML-KEM-768",
        stage="certificate/profile",
        fault_family="profile/usage-policy",
        mutation="Zero all keyUsage bits in the ML-KEM-768 certificate while keeping the extension present.",
        expected_detection=("MLKEM-CERT-KU-KEYENCIPHERMENT-ONLY",),
        mutation_family=("keyusage-empty",),
        operation="certificate_keyusage_zero_bits",
    ),
    DerMutationSpec(
        artifact_id="der-mut-mldsa65-cert-keyusage-empty",
        source_path="corpus/valid/openssl/openssl_mldsa65_ee_cert.pem",
        output_path="corpus/mutated/der/der_mut_mldsa65_cert_keyusage_empty.pem",
        artifact_type="certificate",
        algorithm="ML-DSA",
        parameter_set="ML-DSA-65",
        stage="certificate/profile",
        fault_family="profile/usage-policy",
        mutation="Zero all keyUsage bits in the ML-DSA-65 certificate while keeping the extension present.",
        expected_detection=("MLDSA-CERT-KU-AT-LEAST-ONE-SIGNING-BIT",),
        mutation_family=("keyusage-empty",),
        operation="certificate_keyusage_zero_bits",
    ),
    DerMutationSpec(
        artifact_id="der-mut-mlkem512-key-seed-short",
        source_path="corpus/valid/openssl/openssl_mlkem512_ee_key.pem",
        output_path="corpus/mutated/der/der_mut_mlkem512_key_seed_short.pem",
        artifact_type="private-key-container",
        algorithm="ML-KEM",
        parameter_set="ML-KEM-512",
        stage="private-key-container/import",
        fault_family="size/shape",
        mutation="Shorten the ML-KEM-512 seed inside the private-key both container by one byte.",
        expected_detection=("MLKEM-PRIVATE-SEED-LENGTH",),
        mutation_family=("private-key-seed-length-short",),
        operation="private_key_both_seed_delta",
        args={"delta": -1},
    ),
    DerMutationSpec(
        artifact_id="der-mut-mlkem512-key-expanded-short",
        source_path="corpus/valid/openssl/openssl_mlkem512_ee_key.pem",
        output_path="corpus/mutated/der/der_mut_mlkem512_key_expanded_short.pem",
        artifact_type="private-key-container",
        algorithm="ML-KEM",
        parameter_set="ML-KEM-512",
        stage="private-key-container/import",
        fault_family="size/shape",
        mutation="Shorten the ML-KEM-512 expanded private key inside the both container by one byte.",
        expected_detection=("MLKEM-PRIVATE-EXPANDED-LENGTH",),
        mutation_family=("private-key-expanded-length-short",),
        operation="private_key_both_expanded_delta",
        args={"delta": -1},
    ),
    DerMutationSpec(
        artifact_id="der-mut-mldsa44-key-seed-short",
        source_path="corpus/valid/openssl/openssl_mldsa44_ee_key.pem",
        output_path="corpus/mutated/der/der_mut_mldsa44_key_seed_short.pem",
        artifact_type="private-key-container",
        algorithm="ML-DSA",
        parameter_set="ML-DSA-44",
        stage="private-key-container/import",
        fault_family="size/shape",
        mutation="Shorten the ML-DSA-44 seed inside the private-key both container by one byte.",
        expected_detection=("MLDSA-PRIVATE-SEED-LENGTH",),
        mutation_family=("private-key-seed-length-short",),
        operation="private_key_both_seed_delta",
        args={"delta": -1},
    ),
    DerMutationSpec(
        artifact_id="der-mut-mldsa44-key-expanded-short",
        source_path="corpus/valid/openssl/openssl_mldsa44_ee_key.pem",
        output_path="corpus/mutated/der/der_mut_mldsa44_key_expanded_short.pem",
        artifact_type="private-key-container",
        algorithm="ML-DSA",
        parameter_set="ML-DSA-44",
        stage="private-key-container/import",
        fault_family="size/shape",
        mutation="Shorten the ML-DSA-44 expanded private key inside the both container by one byte.",
        expected_detection=("MLDSA-PRIVATE-EXPANDED-LENGTH",),
        mutation_family=("private-key-expanded-length-short",),
        operation="private_key_both_expanded_delta",
        args={"delta": -1},
    ),
    DerMutationSpec(
        artifact_id="der-mut-mlkem512-key-both-mismatch",
        source_path="corpus/valid/openssl/openssl_mlkem512_ee_key.pem",
        output_path="corpus/mutated/der/der_mut_mlkem512_key_both_mismatch.pem",
        artifact_type="private-key-container",
        algorithm="ML-KEM",
        parameter_set="ML-KEM-512",
        stage="private-key-container/import",
        fault_family="inter-field-consistency",
        mutation="Flip one seed byte in the ML-KEM-512 both container while keeping lengths valid.",
        expected_detection=("MLKEM-PRIVATE-BOTH-CONSISTENCY",),
        mutation_family=("private-key-both-seed-expanded-mismatch",),
        operation="private_key_both_seed_flip",
        args={"offset": 0, "xor": 1},
    ),
    DerMutationSpec(
        artifact_id="der-mut-mlkem512-key-hash-mismatch",
        source_path="corpus/valid/openssl/openssl_mlkem512_ee_key.pem",
        output_path="corpus/mutated/der/der_mut_mlkem512_key_hash_mismatch.pem",
        artifact_type="private-key-container",
        algorithm="ML-KEM",
        parameter_set="ML-KEM-512",
        stage="private-key-container/import",
        fault_family="import-validation",
        mutation="Flip one byte of the stored H(ek) inside the ML-KEM-512 expanded private key while keeping lengths valid.",
        expected_detection=("MLKEM-PRIVATE-EXPANDED-HASH-CHECK", "MLKEM-PRIVATE-BOTH-CONSISTENCY"),
        mutation_family=("mlkem-expanded-key-hash-mismatch",),
        operation="private_key_mlkem_hash_flip",
        args={"parameter_set": "ML-KEM-512", "offset": 0, "xor": 1},
    ),
    DerMutationSpec(
        artifact_id="der-mut-mldsa44-key-both-mismatch",
        source_path="corpus/valid/openssl/openssl_mldsa44_ee_key.pem",
        output_path="corpus/mutated/der/der_mut_mldsa44_key_both_mismatch.pem",
        artifact_type="private-key-container",
        algorithm="ML-DSA",
        parameter_set="ML-DSA-44",
        stage="private-key-container/import",
        fault_family="inter-field-consistency",
        mutation="Flip one seed byte in the ML-DSA-44 both container while keeping lengths valid.",
        expected_detection=("MLDSA-PRIVATE-BOTH-CONSISTENCY",),
        mutation_family=("private-key-both-seed-expanded-mismatch",),
        operation="private_key_both_seed_flip",
        args={"offset": 0, "xor": 1},
    ),
]


def encode_length(length: int) -> bytes:
    if length < 0:
        raise ValueError("negative DER length")
    if length < 128:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def encode_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + encode_length(len(value)) + value


def encode_oid(oid: str) -> bytes:
    arcs = [int(part) for part in oid.split(".")]
    if len(arcs) < 2 or arcs[0] not in {0, 1, 2}:
        raise ValueError(f"unsupported OID: {oid}")
    first_value = arcs[0] * 40 + arcs[1]
    encoded = bytearray(_base128(first_value))
    for arc in arcs[2:]:
        encoded.extend(_base128(arc))
    return encode_tlv(0x06, bytes(encoded))


def _base128(value: int) -> bytes:
    if value < 0:
        raise ValueError("negative OID arc")
    stack = [value & 0x7F]
    value >>= 7
    while value:
        stack.append(0x80 | (value & 0x7F))
        value >>= 7
    return bytes(reversed(stack))


def encode_bit_string(payload: bytes, unused_bits: int = 0) -> bytes:
    if unused_bits:
        raise ValueError("this mutator only emits byte-aligned BIT STRINGs")
    return encode_tlv(0x03, bytes([unused_bits]) + payload)


def add_params_to_algorithm(algorithm: DERNode, params_der: bytes) -> bytes:
    children = algorithm.children()
    if len(children) != 1:
        raise DERError("AlgorithmIdentifier is not parameter-absent")
    return encode_tlv(0x30, children[0].encoded + params_der)


def add_null_params_to_algorithm(algorithm: DERNode) -> bytes:
    return add_params_to_algorithm(algorithm, NULL_DER)


def add_octet_params_to_algorithm(algorithm: DERNode) -> bytes:
    return add_params_to_algorithm(algorithm, OCTET_ZERO_DER)


def replace_algorithm_oid(algorithm: DERNode, new_oid: str) -> bytes:
    children = algorithm.children()
    if not children:
        raise DERError("empty AlgorithmIdentifier")
    suffix = b"".join(child.encoded for child in children[1:])
    return encode_tlv(0x30, encode_oid(new_oid) + suffix)


def mutate_spki_add_null_params(data: bytes) -> bytes:
    algorithm, public_key = _spki_parts(data)
    return encode_tlv(0x30, add_null_params_to_algorithm(algorithm) + public_key.encoded)


def mutate_spki_add_octet_params(data: bytes) -> bytes:
    algorithm, public_key = _spki_parts(data)
    return encode_tlv(0x30, add_octet_params_to_algorithm(algorithm) + public_key.encoded)


def mutate_spki_replace_oid(data: bytes, new_oid: str) -> bytes:
    algorithm, public_key = _spki_parts(data)
    return encode_tlv(0x30, replace_algorithm_oid(algorithm, new_oid) + public_key.encoded)


def mutate_spki_payload_delta(data: bytes, delta: int) -> bytes:
    algorithm, public_key = _spki_parts(data)
    payload = bit_string_payload(public_key)
    if delta < 0:
        if len(payload) <= abs(delta):
            raise DERError("payload delta would remove the entire SPKI payload")
        mutated_payload = payload[:delta]
    else:
        mutated_payload = payload + (b"\x00" * delta)
    return encode_tlv(0x30, algorithm.encoded + encode_bit_string(mutated_payload))


def mutate_spki_payload_target_length(data: bytes, length: int) -> bytes:
    algorithm, public_key = _spki_parts(data)
    payload = bit_string_payload(public_key)
    if length < 0:
        raise ValueError("target payload length must be non-negative")
    if length <= len(payload):
        mutated_payload = payload[:length]
    else:
        mutated_payload = payload + (b"\x00" * (length - len(payload)))
    return encode_tlv(0x30, algorithm.encoded + encode_bit_string(mutated_payload))


def mutate_spki_mlkem_unreduced_value(
    data: bytes,
    coefficient_index: int,
    value: int,
) -> bytes:
    if coefficient_index < 0:
        raise ValueError("coefficient_index must be non-negative")
    if not (0 <= value < 4096):
        raise ValueError("ML-KEM ByteEncode12 value must be in [0, 4095]")
    algorithm, public_key = _spki_parts(data)
    payload = bytearray(bit_string_payload(public_key))
    if len(payload) < 35:
        raise DERError("ML-KEM payload too short for encoded-key plus seed")
    encoded_length = len(payload) - 32
    coeff_count = (encoded_length * 8) // 12
    if coefficient_index >= coeff_count:
        raise ValueError("coefficient_index out of range for ML-KEM payload")
    byte_offset = (coefficient_index * 12) // 8
    if coefficient_index % 2 == 0:
        payload[byte_offset] = value & 0xFF
        payload[byte_offset + 1] = (payload[byte_offset + 1] & 0xF0) | ((value >> 8) & 0x0F)
    else:
        payload[byte_offset] = (payload[byte_offset] & 0x0F) | ((value & 0x0F) << 4)
        payload[byte_offset + 1] = (value >> 4) & 0xFF
    return encode_tlv(0x30, algorithm.encoded + encode_bit_string(bytes(payload)))


def mutate_certificate_spki_add_null_params(data: bytes) -> bytes:
    return _mutate_certificate_spki(data, mutate_spki_add_null_params)


def mutate_certificate_spki_add_octet_params(data: bytes) -> bytes:
    return _mutate_certificate_spki(data, mutate_spki_add_octet_params)


def mutate_certificate_spki_payload_delta(data: bytes, delta: int) -> bytes:
    return _mutate_certificate_spki(
        data,
        lambda spki_der: mutate_spki_payload_delta(spki_der, delta),
    )


def mutate_certificate_signature_add_null_params(data: bytes) -> bytes:
    return _mutate_certificate_signature_params(data, add_null_params_to_algorithm)


def mutate_certificate_signature_add_octet_params(data: bytes) -> bytes:
    return _mutate_certificate_signature_params(data, add_octet_params_to_algorithm)


def mutate_certificate_signature_replace_oid(data: bytes, new_oid: str) -> bytes:
    return _mutate_certificate_signature_params(
        data,
        lambda algorithm: replace_algorithm_oid(algorithm, new_oid),
    )


def mutate_certificate_keyusage_zero_bits(data: bytes) -> bytes:
    root, cert_children = _certificate_parts(data)
    tbs = cert_children[0]
    tbs_children = tbs.children()
    extensions_index = _find_extensions_index(tbs_children)
    if extensions_index is None:
        raise DERError("TBSCertificate does not contain extensions")
    new_extensions = _mutate_extensions_keyusage_zero_bits(tbs_children[extensions_index])
    new_tbs = _rebuild_constructed(tbs, tbs_children, {extensions_index: new_extensions})
    return _rebuild_constructed(root, cert_children, {0: new_tbs})


def mutate_private_key_both_seed_delta(data: bytes, delta: int) -> bytes:
    return _mutate_private_key_both_component(data, 0, delta)


def mutate_private_key_both_expanded_delta(data: bytes, delta: int) -> bytes:
    return _mutate_private_key_both_component(data, 1, delta)


def mutate_private_key_both_seed_flip(data: bytes, offset: int, xor: int) -> bytes:
    return _mutate_private_key_both_component_flip(data, 0, offset, xor)


def mutate_private_key_mlkem_hash_flip(data: bytes, parameter_set: str, offset: int, xor: int) -> bytes:
    hash_offset = _mlkem_expanded_hash_offset(parameter_set)
    return _mutate_private_key_both_component_flip(data, 1, hash_offset + offset, xor)


def _mutate_certificate_signature_params(data: bytes, algorithm_mutator: Any) -> bytes:
    root, cert_children = _certificate_parts(data)
    tbs = cert_children[0]
    tbs_children = tbs.children()
    tbs_signature_index = _tbs_index_after_version(tbs_children) + 1
    new_tbs_signature = algorithm_mutator(tbs_children[tbs_signature_index])
    new_tbs = _rebuild_constructed(tbs, tbs_children, {tbs_signature_index: new_tbs_signature})
    new_outer_signature = algorithm_mutator(cert_children[1])
    return _rebuild_constructed(root, cert_children, {0: new_tbs, 1: new_outer_signature})


def apply_mutation(data: bytes, operation: str, args: Dict[str, Any] | None = None) -> bytes:
    args = args or {}
    if operation == "spki_add_null_params":
        return mutate_spki_add_null_params(data)
    if operation == "spki_add_octet_params":
        return mutate_spki_add_octet_params(data)
    if operation == "spki_replace_oid":
        return mutate_spki_replace_oid(data, str(args["oid"]))
    if operation == "spki_payload_delta":
        return mutate_spki_payload_delta(data, int(args["delta"]))
    if operation == "spki_payload_target_length":
        return mutate_spki_payload_target_length(data, int(args["length"]))
    if operation == "spki_mlkem_unreduced_value":
        return mutate_spki_mlkem_unreduced_value(
            data,
            int(args["coefficient_index"]),
            int(args["value"]),
        )
    if operation == "certificate_spki_add_null_params":
        return mutate_certificate_spki_add_null_params(data)
    if operation == "certificate_spki_add_octet_params":
        return mutate_certificate_spki_add_octet_params(data)
    if operation == "certificate_spki_payload_delta":
        return mutate_certificate_spki_payload_delta(data, int(args["delta"]))
    if operation == "certificate_signature_add_null_params":
        return mutate_certificate_signature_add_null_params(data)
    if operation == "certificate_signature_add_octet_params":
        return mutate_certificate_signature_add_octet_params(data)
    if operation == "certificate_signature_replace_oid":
        return mutate_certificate_signature_replace_oid(data, str(args["oid"]))
    if operation == "certificate_keyusage_zero_bits":
        return mutate_certificate_keyusage_zero_bits(data)
    if operation == "private_key_both_seed_delta":
        return mutate_private_key_both_seed_delta(data, int(args["delta"]))
    if operation == "private_key_both_expanded_delta":
        return mutate_private_key_both_expanded_delta(data, int(args["delta"]))
    if operation == "private_key_both_seed_flip":
        return mutate_private_key_both_seed_flip(data, int(args["offset"]), int(args["xor"]))
    if operation == "private_key_mlkem_hash_flip":
        return mutate_private_key_mlkem_hash_flip(
            data,
            str(args["parameter_set"]),
            int(args["offset"]),
            int(args["xor"]),
        )
    raise ValueError(f"unknown DER mutation operation: {operation}")


def generate_mutations(root: Path, specs: Iterable[DerMutationSpec] = DER_MUTATION_SPECS) -> List[Path]:
    written: List[Path] = []
    for spec in specs:
        source = root / spec.source_path
        output = root / spec.output_path
        label, data = load_pem_or_der(source)
        mutated = apply_mutation(data, spec.operation, spec.args)
        output.parent.mkdir(parents=True, exist_ok=True)
        write_pem_or_der(output, label, mutated)
        written.append(output)
    return written


def load_pem_or_der(path: Path) -> Tuple[str | None, bytes]:
    data = path.read_bytes()
    if not data.startswith(b"-----BEGIN"):
        return None, data
    text = data.decode("ascii")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    begin = lines[0]
    if not begin.startswith("-----BEGIN ") or not begin.endswith("-----"):
        raise ValueError(f"malformed PEM begin line in {path}")
    label = begin[len("-----BEGIN ") : -len("-----")]
    body = [line for line in lines[1:] if not line.startswith("-----")]
    return label, base64.b64decode("".join(body), validate=True)


def write_pem_or_der(path: Path, label: str | None, data: bytes) -> None:
    if label is None:
        path.write_bytes(data)
        return
    b64 = base64.b64encode(data).decode("ascii")
    wrapped = "\n".join(b64[index : index + 64] for index in range(0, len(b64), 64))
    path.write_text(f"-----BEGIN {label}-----\n{wrapped}\n-----END {label}-----\n", encoding="ascii")


def _spki_parts(data: bytes) -> Tuple[DERNode, DERNode]:
    root = parse_der(data)
    if root.tag != 0x30:
        raise DERError("SubjectPublicKeyInfo is not a SEQUENCE")
    children = root.children()
    if len(children) != 2:
        raise DERError("SubjectPublicKeyInfo must contain algorithm and subjectPublicKey")
    return children[0], children[1]


def _certificate_parts(data: bytes) -> Tuple[DERNode, List[DERNode]]:
    root = parse_der(data)
    if root.tag != 0x30:
        raise DERError("certificate is not a SEQUENCE")
    children = root.children()
    if len(children) != 3:
        raise DERError("certificate SEQUENCE must contain exactly three children")
    return root, children


def _mutate_certificate_spki(data: bytes, spki_mutator: Any) -> bytes:
    root, cert_children = _certificate_parts(data)
    tbs = cert_children[0]
    tbs_children = tbs.children()
    spki_index = _tbs_index_after_version(tbs_children) + 5
    if len(tbs_children) <= spki_index:
        raise DERError("TBSCertificate is too short to contain SubjectPublicKeyInfo")
    new_spki = spki_mutator(tbs_children[spki_index].encoded)
    new_tbs = _rebuild_constructed(tbs, tbs_children, {spki_index: new_spki})
    return _rebuild_constructed(root, cert_children, {0: new_tbs})


def _find_extensions_index(tbs_children: List[DERNode]) -> int | None:
    for index, child in enumerate(tbs_children):
        if child.tag == 0xA3:
            return index
    return None


def _mutate_extensions_keyusage_zero_bits(extensions_wrapper: DERNode) -> bytes:
    explicit_children = extensions_wrapper.children()
    if len(explicit_children) != 1 or explicit_children[0].tag != 0x30:
        raise DERError("malformed explicit extensions wrapper")
    extensions = explicit_children[0]
    extension_children = extensions.children()
    replacements: Dict[int, bytes] = {}
    found = False
    for index, extension in enumerate(extension_children):
        parts = extension.children()
        if len(parts) < 2:
            raise DERError("malformed extension")
        if parts[0].tag != 0x06:
            raise DERError("extension extnID is not an OID")
        if oid(parts[0]) != OID_KEY_USAGE:
            continue
        found = True
        value_index = 2 if len(parts) >= 3 and parts[1].tag == 0x01 else 1
        if parts[value_index].tag != 0x04:
            raise DERError("keyUsage extnValue is not an OCTET STRING")
        zero_bits = encode_tlv(0x04, encode_bit_string(b"\x00"))
        replacements[index] = _rebuild_constructed(extension, parts, {value_index: zero_bits})
        break
    if not found:
        raise DERError("keyUsage extension not found")
    rebuilt_extensions = _rebuild_constructed(extensions, extension_children, replacements)
    return encode_tlv(0xA3, rebuilt_extensions)


def _private_key_parts(data: bytes) -> Tuple[DERNode, List[DERNode], DERNode, List[DERNode]]:
    root = parse_der(data)
    if root.tag != 0x30:
        raise DERError("PrivateKeyInfo is not a SEQUENCE")
    outer_children = root.children()
    if len(outer_children) < 3:
        raise DERError("PrivateKeyInfo must contain version, algorithm, and privateKey")
    private_key = outer_children[2]
    if private_key.tag != 0x04:
        raise DERError("PrivateKeyInfo privateKey field is not an OCTET STRING")
    inner = parse_der(private_key.value)
    if inner.tag != 0x30:
        raise DERError("private key payload is not the supported SEQUENCE(both) form")
    inner_children = inner.children()
    if len(inner_children) != 2 or any(child.tag != 0x04 for child in inner_children):
        raise DERError("private key both form must contain exactly two OCTET STRING children")
    return root, outer_children, inner, inner_children


def _mutate_private_key_both_component(data: bytes, index: int, delta: int) -> bytes:
    root, outer_children, inner, inner_children = _private_key_parts(data)
    payload = inner_children[index].value
    if delta < 0:
        if len(payload) <= abs(delta):
            raise DERError("private-key delta would remove the entire OCTET STRING payload")
        mutated_payload = payload[:delta]
    else:
        mutated_payload = payload + (b"\x00" * delta)
    new_inner = _rebuild_constructed(
        inner,
        inner_children,
        {index: encode_tlv(0x04, mutated_payload)},
    )
    new_outer_private_key = encode_tlv(0x04, new_inner)
    return _rebuild_constructed(root, outer_children, {2: new_outer_private_key})


def _mutate_private_key_both_component_flip(data: bytes, index: int, offset: int, xor: int) -> bytes:
    root, outer_children, inner, inner_children = _private_key_parts(data)
    payload = bytearray(inner_children[index].value)
    if offset < 0 or offset >= len(payload):
        raise DERError("private-key byte flip offset is out of bounds")
    payload[offset] ^= xor & 0xFF
    new_inner = _rebuild_constructed(
        inner,
        inner_children,
        {index: encode_tlv(0x04, bytes(payload))},
    )
    new_outer_private_key = encode_tlv(0x04, new_inner)
    return _rebuild_constructed(root, outer_children, {2: new_outer_private_key})


def _mlkem_expanded_hash_offset(parameter_set: str) -> int:
    if parameter_set == "ML-KEM-512":
        return 768 + 800
    if parameter_set == "ML-KEM-768":
        return 1152 + 1184
    if parameter_set == "ML-KEM-1024":
        return 1536 + 1568
    raise ValueError(f"unsupported ML-KEM parameter set for hash mutation: {parameter_set}")


def _rebuild_constructed(node: DERNode, children: List[DERNode], replacements: Dict[int, bytes]) -> bytes:
    value = b"".join(replacements.get(index, child.encoded) for index, child in enumerate(children))
    return encode_tlv(node.tag, value)


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args(argv)
    root = args.root.resolve()
    written = generate_mutations(root)
    for path in written:
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
