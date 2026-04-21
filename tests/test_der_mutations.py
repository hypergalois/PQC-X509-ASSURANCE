import unittest

from pathlib import Path

from pqc_x509_assurance.der_mutations import (
    encode_bit_string,
    encode_oid,
    encode_tlv,
    mutate_certificate_keyusage_zero_bits,
    mutate_certificate_signature_add_octet_params,
    mutate_certificate_signature_add_null_params,
    mutate_certificate_signature_replace_oid,
    mutate_spki_add_octet_params,
    mutate_spki_add_null_params,
    mutate_spki_mlkem_unreduced_value,
    mutate_spki_payload_target_length,
    mutate_spki_replace_oid,
)
from pqc_x509_assurance.x509 import lint_certificate_der, lint_spki_der, load_der


MLKEM768_OID = "2.16.840.1.101.3.4.4.2"
MLDSA44_OID = "2.16.840.1.101.3.4.3.17"
MLDSA65_OID = "2.16.840.1.101.3.4.3.18"
MLDSA87_OID = "2.16.840.1.101.3.4.3.19"
HASHMLDSA44_OID = "2.16.840.1.101.3.4.3.32"
ROOT = Path(__file__).resolve().parents[1]


def seq(*items):
    return encode_tlv(0x30, b"".join(items))


def integer(value):
    if value == 0:
        raw = b"\x00"
    else:
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw
    return encode_tlv(0x02, raw)


def octet_string(payload):
    return encode_tlv(0x04, payload)


def explicit(tag_no, payload):
    return encode_tlv(0xA0 + tag_no, payload)


def alg_id(name):
    return seq(encode_oid(name))


def extension(extn_oid, inner_der):
    return seq(encode_oid(extn_oid), octet_string(inner_der))


def make_spki(spki_oid, public_key_len):
    return seq(alg_id(spki_oid), encode_bit_string(bytes(public_key_len)))


def make_cert(spki_oid, public_key_len):
    spki = make_spki(spki_oid, public_key_len)
    extensions = explicit(3, seq(extension("2.5.29.15", encode_bit_string(b"\x80"))))
    tbs = seq(
        explicit(0, integer(2)),
        integer(1),
        alg_id(MLDSA65_OID),
        seq(),
        seq(),
        seq(),
        spki,
        extensions,
    )
    return seq(tbs, alg_id(MLDSA65_OID), encode_bit_string(b"\x00"))


def findings_by_requirement(findings):
    by_requirement = {}
    for finding in findings:
        by_requirement.setdefault(finding["requirement_id"], []).append(finding["status"])
    return by_requirement


class DERMutationTests(unittest.TestCase):
    def test_spki_null_params_mutation_is_deterministic_and_detected(self):
        spki = make_spki(MLKEM768_OID, 1184)
        first = mutate_spki_add_null_params(spki)
        second = mutate_spki_add_null_params(spki)

        self.assertEqual(first, second)
        result = findings_by_requirement(lint_spki_der(first))
        self.assertEqual(result["MLKEM-SPKI-AID-PARAMS-ABSENT"], ["error"])

    def test_spki_non_null_params_are_detected(self):
        spki = make_spki(MLDSA65_OID, 1952)
        mutated = mutate_spki_add_octet_params(spki)

        result = findings_by_requirement(lint_spki_der(mutated))
        self.assertEqual(result["MLDSA-SPKI-AID-PARAMS-ABSENT"], ["error"])

    def test_spki_payload_2602_exercises_mldsa87_size_conflict(self):
        spki = make_spki(MLDSA87_OID, 2592)
        mutated = mutate_spki_payload_target_length(spki, 2602)

        result = findings_by_requirement(lint_spki_der(mutated))
        self.assertEqual(result["MLDSA-SPKI-PUBLIC-KEY-LENGTH"], ["error"])

    def test_spki_oid_swap_keeps_der_parseable_and_detects_length_mismatch(self):
        spki = make_spki(MLDSA65_OID, 1952)
        mutated = mutate_spki_replace_oid(spki, MLKEM768_OID)

        result = findings_by_requirement(lint_spki_der(mutated))
        self.assertEqual(result["MLKEM-SPKI-PUBLIC-KEY-LENGTH"], ["error"])

    def test_mlkem_spki_unreduced_value_is_detected(self):
        spki = make_spki(MLKEM768_OID, 1184)
        mutated = mutate_spki_mlkem_unreduced_value(spki, 0, 4095)

        result = findings_by_requirement(lint_spki_der(mutated))
        self.assertEqual(result["MLKEM-SPKI-PUBLIC-KEY-LENGTH"], ["pass"])
        self.assertEqual(result["MLKEM-SPKI-ENCODE-DECODE-IDENTITY"], ["error"])

    def test_certificate_signature_null_params_are_detected(self):
        cert = make_cert(MLDSA44_OID, 1312)
        mutated = mutate_certificate_signature_add_null_params(cert)

        result = findings_by_requirement(lint_certificate_der(mutated))
        self.assertEqual(
            result["MLDSA-CERT-SIGNATURE-AID-PARAMS-ABSENT"],
            ["error", "error"],
        )

    def test_certificate_signature_non_null_params_are_detected(self):
        cert = make_cert(MLDSA44_OID, 1312)
        mutated = mutate_certificate_signature_add_octet_params(cert)

        result = findings_by_requirement(lint_certificate_der(mutated))
        self.assertEqual(
            result["MLDSA-CERT-SIGNATURE-AID-PARAMS-ABSENT"],
            ["error", "error"],
        )

    def test_certificate_signature_hashmldsa_oid_is_detected(self):
        cert = make_cert(MLDSA44_OID, 1312)
        mutated = mutate_certificate_signature_replace_oid(cert, HASHMLDSA44_OID)

        result = findings_by_requirement(lint_certificate_der(mutated))
        self.assertEqual(result["MLDSA-PKIX-HASHML-FORBIDDEN"], ["error"])

    def test_mlkem_certificate_keyusage_zero_bits_is_detected(self):
        cert = load_der(ROOT / "corpus" / "valid" / "openssl" / "openssl_mlkem768_ee_cert.pem")
        mutated = mutate_certificate_keyusage_zero_bits(cert)

        result = findings_by_requirement(lint_certificate_der(mutated))
        self.assertEqual(result["MLKEM-CERT-KU-KEYENCIPHERMENT-ONLY"], ["error"])

    def test_mldsa_certificate_keyusage_zero_bits_is_detected(self):
        cert = load_der(ROOT / "corpus" / "valid" / "openssl" / "openssl_mldsa65_ee_cert.pem")
        mutated = mutate_certificate_keyusage_zero_bits(cert)

        result = findings_by_requirement(lint_certificate_der(mutated))
        self.assertEqual(result["MLDSA-CERT-KU-AT-LEAST-ONE-SIGNING-BIT"], ["error"])
        self.assertEqual(result["MLDSA-CERT-KU-NO-ENCIPHERMENT-OR-AGREEMENT"], ["pass"])


if __name__ == "__main__":
    unittest.main()
