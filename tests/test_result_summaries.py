import unittest

from pqc_x509_assurance.run_extended import summarize_findings


def finding(requirement_id, status="error"):
    return {
        "requirement_id": requirement_id,
        "detector": "detector.test",
        "status": status,
        "message": "test finding",
    }


class ResultSummaryTests(unittest.TestCase):
    def test_summary_deduplicates_repeated_errors_without_losing_counts(self):
        summary = summarize_findings(
            [
                finding("REQ-A"),
                finding("REQ-A"),
                finding("REQ-B", "pass"),
            ],
            {"REQ-A"},
        )

        self.assertEqual(summary["detected_requirements"], ["REQ-A"])
        self.assertEqual(summary["error_count"], 2)
        self.assertEqual(summary["unique_error_count"], 1)
        self.assertEqual(summary["redundant_error_count"], 1)
        self.assertEqual(summary["error_instances_by_requirement"], {"REQ-A": 2})
        self.assertEqual(summary["first_error_requirement"], "REQ-A")
        self.assertEqual(summary["first_expected_requirement"], "REQ-A")
        self.assertEqual(summary["missing_expected_requirements"], [])
        self.assertEqual(summary["unexpected_error_requirements"], [])

    def test_summary_separates_first_error_from_first_expected_hit(self):
        summary = summarize_findings(
            [
                finding("REQ-UNEXPECTED"),
                finding("REQ-EXPECTED"),
            ],
            {"REQ-EXPECTED"},
        )

        self.assertTrue(summary["expected_detection_met"])
        self.assertEqual(summary["first_error_requirement"], "REQ-UNEXPECTED")
        self.assertEqual(summary["first_expected_requirement"], "REQ-EXPECTED")
        self.assertEqual(summary["unexpected_error_requirements"], ["REQ-UNEXPECTED"])
        self.assertEqual(summary["missing_expected_requirements"], [])

    def test_summary_reports_missing_expected_requirements(self):
        summary = summarize_findings([], {"REQ-A"})

        self.assertFalse(summary["expected_detection_met"])
        self.assertEqual(summary["detected_requirements"], [])
        self.assertEqual(summary["missing_expected_requirements"], ["REQ-A"])
        self.assertIsNone(summary["first_error_requirement"])
        self.assertIsNone(summary["first_expected_requirement"])


if __name__ == "__main__":
    unittest.main()
