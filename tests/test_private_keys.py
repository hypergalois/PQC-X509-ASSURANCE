from pathlib import Path
import unittest

from pqc_x509_assurance.der_mutations import (
    encode_oid,
    encode_tlv,
    mutate_private_key_both_expanded_delta,
    mutate_private_key_both_seed_flip,
    mutate_private_key_mlkem_hash_flip,
    mutate_private_key_both_seed_delta,
)
from pqc_x509_assurance.private_keys import lint_private_key_container_der
from pqc_x509_assurance.import_validation import resolve_bridge_binary
from pqc_x509_assurance.x509 import load_der


MLKEM512_OID = "2.16.840.1.101.3.4.4.1"
MLDSA44_OID = "2.16.840.1.101.3.4.3.17"
ROOT = Path(__file__).resolve().parents[1]
HAS_BRIDGE = resolve_bridge_binary() is not None


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


def alg_id(name):
    return seq(encode_oid(name))


def private_key_info(private_key_oid, seed_length, expanded_length):
    both = seq(octet_string(bytes(seed_length)), octet_string(bytes(expanded_length)))
    return seq(integer(0), alg_id(private_key_oid), octet_string(both))


def statuses(findings):
    return {finding["requirement_id"]: finding["status"] for finding in findings}


class PrivateKeyLintTests(unittest.TestCase):
    @unittest.skipUnless(HAS_BRIDGE, "libcrux import bridge not available")
    def test_mlkem_both_private_key_passes_length_checks(self):
        container = private_key_info(MLKEM512_OID, 64, 1632)

        result = statuses(lint_private_key_container_der(container))
        self.assertEqual(result["MLKEM-PRIVATE-SEED-LENGTH"], "pass")
        self.assertEqual(result["MLKEM-PRIVATE-EXPANDED-LENGTH"], "pass")

    @unittest.skipUnless(HAS_BRIDGE, "libcrux import bridge not available")
    def test_mldsa_both_private_key_passes_length_checks(self):
        container = private_key_info(MLDSA44_OID, 32, 2560)

        result = statuses(lint_private_key_container_der(container))
        self.assertEqual(result["MLDSA-PRIVATE-SEED-LENGTH"], "pass")
        self.assertEqual(result["MLDSA-PRIVATE-EXPANDED-LENGTH"], "pass")

    def test_mlkem_seed_short_mutation_is_detected(self):
        container = private_key_info(MLKEM512_OID, 64, 1632)
        mutated = mutate_private_key_both_seed_delta(container, -1)

        result = statuses(lint_private_key_container_der(mutated))
        self.assertEqual(result["MLKEM-PRIVATE-SEED-LENGTH"], "error")
        self.assertEqual(result["MLKEM-PRIVATE-EXPANDED-LENGTH"], "pass")

    def test_mldsa_expanded_short_mutation_is_detected(self):
        container = private_key_info(MLDSA44_OID, 32, 2560)
        mutated = mutate_private_key_both_expanded_delta(container, -1)

        result = statuses(lint_private_key_container_der(mutated))
        self.assertEqual(result["MLDSA-PRIVATE-SEED-LENGTH"], "pass")
        self.assertEqual(result["MLDSA-PRIVATE-EXPANDED-LENGTH"], "error")

    @unittest.skipUnless(HAS_BRIDGE, "libcrux import bridge not available")
    def test_valid_mlkem_private_key_passes_hash_and_consistency_checks(self):
        container = load_der(ROOT / "corpus" / "valid" / "openssl" / "openssl_mlkem512_ee_key.pem")

        result = statuses(lint_private_key_container_der(container))
        self.assertEqual(result["MLKEM-PRIVATE-SEED-LENGTH"], "pass")
        self.assertEqual(result["MLKEM-PRIVATE-EXPANDED-LENGTH"], "pass")
        self.assertEqual(result["MLKEM-PRIVATE-EXPANDED-HASH-CHECK"], "pass")
        self.assertEqual(result["MLKEM-PRIVATE-BOTH-CONSISTENCY"], "pass")

    @unittest.skipUnless(HAS_BRIDGE, "libcrux import bridge not available")
    def test_valid_mldsa_private_key_passes_consistency_check(self):
        container = load_der(ROOT / "corpus" / "valid" / "openssl" / "openssl_mldsa44_ee_key.pem")

        result = statuses(lint_private_key_container_der(container))
        self.assertEqual(result["MLDSA-PRIVATE-SEED-LENGTH"], "pass")
        self.assertEqual(result["MLDSA-PRIVATE-EXPANDED-LENGTH"], "pass")
        self.assertEqual(result["MLDSA-PRIVATE-BOTH-CONSISTENCY"], "pass")

    @unittest.skipUnless(HAS_BRIDGE, "libcrux import bridge not available")
    def test_mlkem_hash_mismatch_mutation_is_detected(self):
        container = load_der(ROOT / "corpus" / "valid" / "openssl" / "openssl_mlkem512_ee_key.pem")
        mutated = mutate_private_key_mlkem_hash_flip(container, "ML-KEM-512", 0, 1)

        result = statuses(lint_private_key_container_der(mutated))
        self.assertEqual(result["MLKEM-PRIVATE-SEED-LENGTH"], "pass")
        self.assertEqual(result["MLKEM-PRIVATE-EXPANDED-LENGTH"], "pass")
        self.assertEqual(result["MLKEM-PRIVATE-EXPANDED-HASH-CHECK"], "error")
        self.assertEqual(result["MLKEM-PRIVATE-BOTH-CONSISTENCY"], "error")

    @unittest.skipUnless(HAS_BRIDGE, "libcrux import bridge not available")
    def test_mldsa_both_mismatch_mutation_is_detected(self):
        container = load_der(ROOT / "corpus" / "valid" / "openssl" / "openssl_mldsa44_ee_key.pem")
        mutated = mutate_private_key_both_seed_flip(container, 0, 1)

        result = statuses(lint_private_key_container_der(mutated))
        self.assertEqual(result["MLDSA-PRIVATE-SEED-LENGTH"], "pass")
        self.assertEqual(result["MLDSA-PRIVATE-EXPANDED-LENGTH"], "pass")
        self.assertEqual(result["MLDSA-PRIVATE-BOTH-CONSISTENCY"], "error")


if __name__ == "__main__":
    unittest.main()
