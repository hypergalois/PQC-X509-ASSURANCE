import unittest

from pqc_x509_assurance.baseline_compare import (
    improvement_class,
    normalize_baseline_result,
)


class BaselineCompareTests(unittest.TestCase):
    def test_normalize_counts_only_error_status_as_detection(self):
        record = {
            "artifact_id": "mut-cert",
            "artifact_type": "certificate",
            "algorithm": "ML-KEM",
            "stage": "certificate/profile",
            "parameter_set": "ML-KEM-768",
            "validity": "invalid",
            "path": "corpus/mut-cert.pem",
            "expected_detection": ["MLKEM-CERT-KU-KEYENCIPHERMENT-ONLY"],
        }
        raw_results = {
            "e_ml_kem_key_usage": {"result": "error"},
            "e_ml_kem_ek_encoding": {"result": "fatal"},
            "e_known_encoded_key": {"result": "pass"},
        }

        result = normalize_baseline_result(record, raw_results, 12.5, "")

        self.assertEqual(result["status"], "error")
        self.assertEqual(
            result["detected_requirements"],
            ["MLKEM-CERT-KU-KEYENCIPHERMENT-ONLY"],
        )
        self.assertEqual(
            result["fatal_requirement_candidates"],
            ["MLKEM-SPKI-ENCODE-DECODE-IDENTITY"],
        )
        self.assertEqual(result["expected_detection_met"], True)

    def test_improvement_class_flags_recovered_detection_with_runtime_fragility(self):
        baseline = {
            "expected_detection_met": False,
            "fatal_lints": ["e_ml_kem_ek_encoding"],
            "status": "fatal",
        }
        extended = {
            "expected_detection_met": True,
            "status": "error",
        }

        self.assertEqual(
            improvement_class(baseline, extended),
            "extended-recovers-baseline-miss-and-runtime-fragility",
        )


if __name__ == "__main__":
    unittest.main()
