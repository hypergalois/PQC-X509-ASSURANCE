import unittest

from pqc_x509_assurance.x509 import lint_certificate_der


def der_len(length):
    if length < 128:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def tlv(tag, value):
    return bytes([tag]) + der_len(len(value)) + value


def seq(*items):
    return tlv(0x30, b"".join(items))


def integer(value):
    if value == 0:
        raw = b"\x00"
    else:
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw
    return tlv(0x02, raw)


def null():
    return b"\x05\x00"


def oid(name):
    arcs = [int(part) for part in name.split(".")]
    first = bytes([40 * arcs[0] + arcs[1]])
    encoded = bytearray(first)
    for arc in arcs[2:]:
        stack = [arc & 0x7F]
        arc >>= 7
        while arc:
            stack.append(0x80 | (arc & 0x7F))
            arc >>= 7
        encoded.extend(reversed(stack))
    return tlv(0x06, bytes(encoded))


def alg_id(name, params=False):
    return seq(oid(name), null() if params else b"")


def bit_string(payload):
    return tlv(0x03, b"\x00" + payload)


def octet_string(payload):
    return tlv(0x04, payload)


def explicit(tag_no, payload):
    return tlv(0xA0 + tag_no, payload)


def extension(extn_oid, inner_der):
    return seq(oid(extn_oid), octet_string(inner_der))


def make_cert(
    spki_oid,
    public_key_len,
    key_usage_payload=None,
    spki_params=False,
    signature_oid="2.16.840.1.101.3.4.3.18",
):
    spki = seq(alg_id(spki_oid, params=spki_params), bit_string(bytes(public_key_len)))
    extensions = b""
    if key_usage_payload is not None:
        extensions = explicit(3, seq(extension("2.5.29.15", bit_string(key_usage_payload))))
    tbs = seq(
        explicit(0, integer(2)),
        integer(1),
        alg_id(signature_oid),
        seq(),
        seq(),
        seq(),
        spki,
        extensions,
    )
    return seq(tbs, alg_id(signature_oid), bit_string(b"\x00"))


def statuses(findings):
    return {finding["requirement_id"]: finding["status"] for finding in findings}


class X509LintTests(unittest.TestCase):
    def test_mlkem_key_usage_accepts_key_encipherment_only(self):
        cert = make_cert("2.16.840.1.101.3.4.4.2", 1184, b"\x20")
        result = statuses(lint_certificate_der(cert))
        self.assertEqual(result["MLKEM-SPKI-AID-PARAMS-ABSENT"], "pass")
        self.assertEqual(result["MLKEM-SPKI-PUBLIC-KEY-LENGTH"], "pass")
        self.assertEqual(result["MLKEM-SPKI-ENCODE-DECODE-IDENTITY"], "pass")
        self.assertEqual(result["MLKEM-CERT-KU-KEYENCIPHERMENT-ONLY"], "pass")

    def test_mlkem_key_usage_rejects_missing_key_encipherment(self):
        cert = make_cert("2.16.840.1.101.3.4.4.2", 1184, b"\x00")
        result = statuses(lint_certificate_der(cert))
        self.assertEqual(result["MLKEM-CERT-KU-KEYENCIPHERMENT-ONLY"], "error")

    def test_mldsa_rejects_encipherment_only_usage(self):
        cert = make_cert("2.16.840.1.101.3.4.3.18", 1952, b"\x20")
        result = statuses(lint_certificate_der(cert))
        self.assertEqual(result["MLDSA-CERT-KU-AT-LEAST-ONE-SIGNING-BIT"], "error")
        self.assertEqual(result["MLDSA-CERT-KU-NO-ENCIPHERMENT-OR-AGREEMENT"], "error")

    def test_mldsa_rejects_null_algorithm_parameters(self):
        cert = make_cert("2.16.840.1.101.3.4.3.18", 1952, b"\x80", spki_params=True)
        result = statuses(lint_certificate_der(cert))
        self.assertEqual(result["MLDSA-SPKI-AID-PARAMS-ABSENT"], "error")
        self.assertEqual(result["MLDSA-CERT-KU-AT-LEAST-ONE-SIGNING-BIT"], "pass")

    def test_mldsa_rejects_hashmldsa_in_pkix_certificate_context(self):
        cert = make_cert(
            "2.16.840.1.101.3.4.3.18",
            1952,
            b"\x80",
            signature_oid="2.16.840.1.101.3.4.3.32",
        )
        result = statuses(lint_certificate_der(cert))
        self.assertEqual(result["MLDSA-PKIX-HASHML-FORBIDDEN"], "error")


if __name__ == "__main__":
    unittest.main()
