"""Narrow X.509 extraction and PQC lint checks."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from .der import DERError, DERNode, bit_string_has_bit, bit_string_payload, oid, parse_der


OID_KEY_USAGE = "2.5.29.15"

MLKEM_OIDS: Dict[str, str] = {
    "2.16.840.1.101.3.4.4.1": "ML-KEM-512",
    "2.16.840.1.101.3.4.4.2": "ML-KEM-768",
    "2.16.840.1.101.3.4.4.3": "ML-KEM-1024",
}
MLKEM_PUBLIC_KEY_LENGTHS = {
    "ML-KEM-512": 800,
    "ML-KEM-768": 1184,
    "ML-KEM-1024": 1568,
}
MLKEM_Q = 3329

MLDSA_OIDS: Dict[str, str] = {
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
}
HASHMLDSA_OIDS: Dict[str, str] = {
    "2.16.840.1.101.3.4.3.32": "HashML-DSA-44",
    "2.16.840.1.101.3.4.3.33": "HashML-DSA-65",
    "2.16.840.1.101.3.4.3.34": "HashML-DSA-87",
}
MLDSA_PUBLIC_KEY_LENGTHS = {
    "ML-DSA-44": 1312,
    "ML-DSA-65": 1952,
    "ML-DSA-87": 2592,
}

KU_DIGITAL_SIGNATURE = 0
KU_NON_REPUDIATION = 1
KU_KEY_ENCIPHERMENT = 2
KU_DATA_ENCIPHERMENT = 3
KU_KEY_AGREEMENT = 4
KU_KEY_CERT_SIGN = 5
KU_CRL_SIGN = 6
KU_ENCIPHER_ONLY = 7
KU_DECIPHER_ONLY = 8

MLDSA_ALLOWED_KU = {
    KU_DIGITAL_SIGNATURE,
    KU_NON_REPUDIATION,
    KU_KEY_CERT_SIGN,
    KU_CRL_SIGN,
}
MLDSA_FORBIDDEN_KU = {
    KU_KEY_ENCIPHERMENT,
    KU_DATA_ENCIPHERMENT,
    KU_KEY_AGREEMENT,
    KU_ENCIPHER_ONLY,
    KU_DECIPHER_ONLY,
}


@dataclass(frozen=True)
class AlgorithmIdentifier:
    oid: str
    parameters_present: bool


@dataclass(frozen=True)
class CertificateView:
    spki_algorithm: AlgorithmIdentifier
    spki_public_key_payload: bytes
    tbs_signature_algorithm: AlgorithmIdentifier
    outer_signature_algorithm: AlgorithmIdentifier
    key_usage: Optional[DERNode]


@dataclass(frozen=True)
class SpkiView:
    algorithm: AlgorithmIdentifier
    public_key_payload: bytes


def load_der(path: Path) -> bytes:
    data = path.read_bytes()
    if data.startswith(b"-----BEGIN"):
        text = data.decode("ascii")
        lines = [
            line.strip()
            for line in text.splitlines()
            if line and not line.startswith("-----")
        ]
        return base64.b64decode("".join(lines), validate=True)
    return data


def parse_algorithm_identifier(node: DERNode) -> AlgorithmIdentifier:
    if node.tag != 0x30:
        raise DERError(f"expected AlgorithmIdentifier SEQUENCE, got 0x{node.tag:02x}")
    children = node.children()
    if not children:
        raise DERError("empty AlgorithmIdentifier")
    return AlgorithmIdentifier(oid=oid(children[0]), parameters_present=len(children) > 1)


def _tbs_children(tbs: DERNode) -> List[DERNode]:
    children = tbs.children()
    if not children:
        raise DERError("empty TBSCertificate")
    return children


def _tbs_index_after_version(children: List[DERNode]) -> int:
    return 1 if children and children[0].tag == 0xA0 else 0


def _extract_extensions(tbs_children: List[DERNode], start_index: int) -> Optional[DERNode]:
    for child in tbs_children[start_index:]:
        if child.tag == 0xA3:
            explicit_children = child.children()
            if len(explicit_children) != 1 or explicit_children[0].tag != 0x30:
                raise DERError("malformed explicit extensions wrapper")
            return explicit_children[0]
    return None


def _extract_key_usage(extensions: Optional[DERNode]) -> Optional[DERNode]:
    if extensions is None:
        return None
    for extension in extensions.children():
        parts = extension.children()
        if len(parts) < 2:
            raise DERError("malformed extension")
        extn_id = oid(parts[0])
        if extn_id != OID_KEY_USAGE:
            continue
        value_node = parts[2] if len(parts) >= 3 and parts[1].tag == 0x01 else parts[1]
        if value_node.tag != 0x04:
            raise DERError("keyUsage extnValue is not an OCTET STRING")
        return parse_der(value_node.value)
    return None


def parse_certificate(data: bytes) -> CertificateView:
    root = parse_der(data)
    if root.tag != 0x30:
        raise DERError("certificate is not a SEQUENCE")
    cert_children = root.children()
    if len(cert_children) != 3:
        raise DERError("certificate SEQUENCE must contain tbsCertificate, signatureAlgorithm, signatureValue")

    tbs = cert_children[0]
    tbs_children = _tbs_children(tbs)
    base = _tbs_index_after_version(tbs_children)
    signature_index = base + 1
    spki_index = base + 5
    if len(tbs_children) <= spki_index:
        raise DERError("TBSCertificate is too short to contain SubjectPublicKeyInfo")

    spki_children = tbs_children[spki_index].children()
    if len(spki_children) != 2:
        raise DERError("SubjectPublicKeyInfo must contain algorithm and subjectPublicKey")

    extensions = _extract_extensions(tbs_children, spki_index + 1)
    return CertificateView(
        spki_algorithm=parse_algorithm_identifier(spki_children[0]),
        spki_public_key_payload=bit_string_payload(spki_children[1]),
        tbs_signature_algorithm=parse_algorithm_identifier(tbs_children[signature_index]),
        outer_signature_algorithm=parse_algorithm_identifier(cert_children[1]),
        key_usage=_extract_key_usage(extensions),
    )


def parse_spki(data: bytes) -> SpkiView:
    root = parse_der(data)
    if root.tag != 0x30:
        raise DERError("SubjectPublicKeyInfo is not a SEQUENCE")
    spki_children = root.children()
    if len(spki_children) != 2:
        raise DERError("SubjectPublicKeyInfo must contain algorithm and subjectPublicKey")
    return SpkiView(
        algorithm=parse_algorithm_identifier(spki_children[0]),
        public_key_payload=bit_string_payload(spki_children[1]),
    )


def lint_certificate_der(data: bytes) -> List[Dict[str, str]]:
    cert = parse_certificate(data)
    findings: List[Dict[str, str]] = []
    spki_oid = cert.spki_algorithm.oid
    spki_param_set = MLKEM_OIDS.get(spki_oid) or MLDSA_OIDS.get(spki_oid)

    if spki_oid in MLKEM_OIDS:
        _record_absent_params(
            findings,
            "MLKEM-SPKI-AID-PARAMS-ABSENT",
            "detector.algorithm_identifier.parameters_absent",
            cert.spki_algorithm,
            "ML-KEM SPKI AlgorithmIdentifier parameters must be absent.",
        )
        _record_payload_length(
            findings,
            "MLKEM-SPKI-PUBLIC-KEY-LENGTH",
            cert.spki_public_key_payload,
            MLKEM_PUBLIC_KEY_LENGTHS[spki_param_set],
            spki_param_set,
        )
        if len(cert.spki_public_key_payload) == MLKEM_PUBLIC_KEY_LENGTHS[spki_param_set]:
            _record_mlkem_encode_decode_identity(findings, cert.spki_public_key_payload)
        if cert.key_usage is not None:
            _record_mlkem_key_usage(findings, cert.key_usage)

    if spki_oid in MLDSA_OIDS:
        _record_absent_params(
            findings,
            "MLDSA-SPKI-AID-PARAMS-ABSENT",
            "detector.algorithm_identifier.parameters_absent",
            cert.spki_algorithm,
            "ML-DSA SPKI AlgorithmIdentifier parameters must be absent.",
        )
        _record_payload_length(
            findings,
            "MLDSA-SPKI-PUBLIC-KEY-LENGTH",
            cert.spki_public_key_payload,
            MLDSA_PUBLIC_KEY_LENGTHS[spki_param_set],
            spki_param_set,
        )
        if cert.key_usage is not None:
            _record_mldsa_key_usage(findings, cert.key_usage)

    for location, algorithm in (
        ("tbsCertificate.signature", cert.tbs_signature_algorithm),
        ("certificate.signatureAlgorithm", cert.outer_signature_algorithm),
    ):
        if algorithm.oid in MLDSA_OIDS:
            _record_absent_params(
                findings,
                "MLDSA-CERT-SIGNATURE-AID-PARAMS-ABSENT",
                "detector.signature_algorithm.mldsa_parameters_absent",
                algorithm,
                f"ML-DSA signature AlgorithmIdentifier parameters must be absent at {location}.",
            )

    if any(
        algorithm.oid in MLDSA_OIDS or algorithm.oid in HASHMLDSA_OIDS
        for algorithm in (cert.tbs_signature_algorithm, cert.outer_signature_algorithm)
    ):
        _record_hashml_dsa_forbidden(findings, cert)

    return findings


def lint_spki_der(data: bytes) -> List[Dict[str, str]]:
    spki = parse_spki(data)
    spki_oid = spki.algorithm.oid
    spki_param_set = MLKEM_OIDS.get(spki_oid) or MLDSA_OIDS.get(spki_oid)
    findings: List[Dict[str, str]] = []

    if spki_oid in MLKEM_OIDS:
        _record_absent_params(
            findings,
            "MLKEM-SPKI-AID-PARAMS-ABSENT",
            "detector.algorithm_identifier.parameters_absent",
            spki.algorithm,
            "ML-KEM SPKI AlgorithmIdentifier parameters must be absent.",
        )
        _record_payload_length(
            findings,
            "MLKEM-SPKI-PUBLIC-KEY-LENGTH",
            spki.public_key_payload,
            MLKEM_PUBLIC_KEY_LENGTHS[spki_param_set],
            spki_param_set,
        )
        if len(spki.public_key_payload) == MLKEM_PUBLIC_KEY_LENGTHS[spki_param_set]:
            _record_mlkem_encode_decode_identity(findings, spki.public_key_payload)

    if spki_oid in MLDSA_OIDS:
        _record_absent_params(
            findings,
            "MLDSA-SPKI-AID-PARAMS-ABSENT",
            "detector.algorithm_identifier.parameters_absent",
            spki.algorithm,
            "ML-DSA SPKI AlgorithmIdentifier parameters must be absent.",
        )
        _record_payload_length(
            findings,
            "MLDSA-SPKI-PUBLIC-KEY-LENGTH",
            spki.public_key_payload,
            MLDSA_PUBLIC_KEY_LENGTHS[spki_param_set],
            spki_param_set,
        )

    return findings


def _append(
    findings: List[Dict[str, str]],
    requirement_id: str,
    detector: str,
    status: str,
    message: str,
) -> None:
    findings.append(
        {
            "requirement_id": requirement_id,
            "detector": detector,
            "status": status,
            "message": message,
        }
    )


def _record_absent_params(
    findings: List[Dict[str, str]],
    requirement_id: str,
    detector: str,
    algorithm: AlgorithmIdentifier,
    message: str,
) -> None:
    _append(
        findings,
        requirement_id,
        detector,
        "error" if algorithm.parameters_present else "pass",
        message if algorithm.parameters_present else "parameters absent",
    )


def _record_payload_length(
    findings: List[Dict[str, str]],
    requirement_id: str,
    payload: bytes,
    expected_length: int,
    parameter_set: str,
) -> None:
    actual = len(payload)
    status = "pass" if actual == expected_length else "error"
    _append(
        findings,
        requirement_id,
        "detector.spki.payload_length",
        status,
        f"{parameter_set} SPKI payload length is {actual}, expected {expected_length}",
    )


def _record_mlkem_key_usage(findings: List[Dict[str, str]], key_usage: DERNode) -> None:
    active_bits = [bit for bit in range(9) if bit_string_has_bit(key_usage, bit)]
    status = "pass" if active_bits == [KU_KEY_ENCIPHERMENT] else "error"
    _append(
        findings,
        "MLKEM-CERT-KU-KEYENCIPHERMENT-ONLY",
        "detector.key_usage.mlkem_key_encipherment_only",
        status,
        f"ML-KEM keyUsage active bits: {active_bits}; expected only [2]",
    )


def _record_mlkem_encode_decode_identity(
    findings: List[Dict[str, str]],
    payload: bytes,
) -> None:
    encoded_t = payload[:-32]
    if len(encoded_t) % 3 != 0:
        _append(
            findings,
            "MLKEM-SPKI-ENCODE-DECODE-IDENTITY",
            "detector.mlkem.encode_decode_identity",
            "error",
            f"ML-KEM encoded public-key portion has length {len(encoded_t)}, which is not divisible by 3.",
        )
        return

    canonical = bytearray()
    mismatch = None
    coefficient_index = 0
    for offset in range(0, len(encoded_t), 3):
        d0 = encoded_t[offset]
        d1 = encoded_t[offset + 1]
        d2 = encoded_t[offset + 2]
        raw_first = d0 | ((d1 & 0x0F) << 8)
        raw_second = (d1 >> 4) | (d2 << 4)
        reduced_first = raw_first % MLKEM_Q
        reduced_second = raw_second % MLKEM_Q
        canonical.extend(
            (
                reduced_first & 0xFF,
                ((reduced_first >> 8) & 0x0F) | ((reduced_second & 0x0F) << 4),
                (reduced_second >> 4) & 0xFF,
            )
        )
        if mismatch is None:
            if raw_first != reduced_first:
                mismatch = (coefficient_index, raw_first, reduced_first)
            elif raw_second != reduced_second:
                mismatch = (coefficient_index + 1, raw_second, reduced_second)
        coefficient_index += 2

    _append(
        findings,
        "MLKEM-SPKI-ENCODE-DECODE-IDENTITY",
        "detector.mlkem.encode_decode_identity",
        "pass" if bytes(canonical) == encoded_t else "error",
        (
            "ML-KEM encoded public key is canonical under ByteDecode12/ByteEncode12."
            if bytes(canonical) == encoded_t
            else (
                f"ML-KEM coefficient {mismatch[0]} decodes to {mismatch[1]} and re-encodes canonically as {mismatch[2]}."
                if mismatch is not None
                else "ML-KEM encoded public key is not canonical under ByteDecode12/ByteEncode12."
            )
        ),
    )


def _record_mldsa_key_usage(findings: List[Dict[str, str]], key_usage: DERNode) -> None:
    active_bits = {bit for bit in range(9) if bit_string_has_bit(key_usage, bit)}
    has_allowed = bool(active_bits & MLDSA_ALLOWED_KU)
    has_forbidden = bool(active_bits & MLDSA_FORBIDDEN_KU)
    _append(
        findings,
        "MLDSA-CERT-KU-AT-LEAST-ONE-SIGNING-BIT",
        "detector.key_usage.mldsa_requires_signing_usage",
        "pass" if has_allowed else "error",
        f"ML-DSA keyUsage active bits: {sorted(active_bits)}; expected at least one of [0, 1, 5, 6]",
    )
    _append(
        findings,
        "MLDSA-CERT-KU-NO-ENCIPHERMENT-OR-AGREEMENT",
        "detector.key_usage.mldsa_forbid_encipherment_agreement",
        "error" if has_forbidden else "pass",
        f"ML-DSA keyUsage active bits: {sorted(active_bits)}; forbidden bits are [2, 3, 4, 7, 8]",
    )


def _record_hashml_dsa_forbidden(
    findings: List[Dict[str, str]],
    cert: CertificateView,
) -> None:
    locations = (
        ("tbsCertificate.signature", cert.tbs_signature_algorithm),
        ("certificate.signatureAlgorithm", cert.outer_signature_algorithm),
    )
    hash_locations = [
        f"{location} uses {HASHMLDSA_OIDS[algorithm.oid]}"
        for location, algorithm in locations
        if algorithm.oid in HASHMLDSA_OIDS
    ]
    _append(
        findings,
        "MLDSA-PKIX-HASHML-FORBIDDEN",
        "detector.algorithm_policy.hashml_dsa_forbidden",
        "error" if hash_locations else "pass",
        "; ".join(hash_locations)
        if hash_locations
        else "certificate uses pure ML-DSA signature identifiers, not HashML-DSA.",
    )
