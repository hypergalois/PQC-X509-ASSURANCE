import unittest
from pathlib import Path
from unittest.mock import patch

from pqc_x509_assurance.cross_tool_behavior import (
    _sanitize_tool_message,
    classify_requirement_ids,
    derive_tool_status,
    run_openssl_behavior,
    summarize_cross_tool_rows,
)


ROOT = Path(__file__).resolve().parents[1]


class CrossToolBehaviorTests(unittest.TestCase):
    def test_requirement_classification_distinguishes_structural_and_semantic(self):
        requirement_map = {
            "REQ-STRUCT": {"detector_kind": "structural"},
            "REQ-POLICY": {"detector_kind": "policy"},
        }

        self.assertEqual(
            classify_requirement_ids(["REQ-STRUCT"], requirement_map),
            "rejected-structural",
        )
        self.assertEqual(
            classify_requirement_ids(["REQ-POLICY"], requirement_map),
            "rejected-semantic",
        )
        self.assertEqual(
            classify_requirement_ids(["REQ-STRUCT", "REQ-POLICY"], requirement_map),
            "rejected-semantic",
        )

    def test_summary_tracks_parse_only_divergence_and_runtime_fragility(self):
        rows = [
            {
                "artifact_id": "a-cert",
                "artifact_type": "certificate",
                "tool": "openssl-cli",
                "behavior": "accepted",
                "validity": "invalid",
            },
            {
                "artifact_id": "a-cert",
                "artifact_type": "certificate",
                "tool": "extended-local",
                "behavior": "rejected-semantic",
                "validity": "invalid",
            },
            {
                "artifact_id": "b-cert",
                "artifact_type": "certificate",
                "tool": "jzlint-baseline",
                "behavior": "runtime-failure",
                "validity": "valid",
            },
            {
                "artifact_id": "c-key",
                "artifact_type": "private-key-container",
                "tool": "openssl-cli",
                "behavior": "accepted",
                "validity": "invalid",
            },
            {
                "artifact_id": "c-key",
                "artifact_type": "private-key-container",
                "tool": "extended-local",
                "behavior": "rejected-semantic",
                "validity": "invalid",
            },
            {
                "artifact_id": "c-key",
                "artifact_type": "private-key-container",
                "tool": "pkilint",
                "behavior": "not-applicable",
                "validity": "invalid",
            },
        ]

        summary = summarize_cross_tool_rows(rows)

        self.assertIn("a-cert", summary["openssl_parse_acceptance_vs_local_rejection"])
        self.assertIn("b-cert", summary["baseline_runtime_fragility_on_valid_certificates"])
        self.assertIn("c-key", summary["openssl_private_key_acceptance_vs_local_semantic_rejection"])
        self.assertEqual(summary["by_tool_behavior"]["pkilint"]["not-applicable"], 1)

    def test_host_unavailability_does_not_count_as_baseline_fragility(self):
        rows = [
            {
                "artifact_id": "u-cert",
                "artifact_type": "certificate",
                "tool": "jzlint-baseline",
                "behavior": "tool-unavailable-on-host",
                "validity": "valid",
            }
        ]

        summary = summarize_cross_tool_rows(rows)

        self.assertEqual(summary["baseline_runtime_fragility_on_valid_certificates"], [])
        self.assertEqual(summary["baseline_host_unavailable_certificates"], ["u-cert"])

    @patch("pqc_x509_assurance.cross_tool_behavior.discover_pkilint_binary", return_value=None)
    @patch("pqc_x509_assurance.cross_tool_behavior.discover_openssl_binary", return_value=None)
    @patch(
        "pqc_x509_assurance.cross_tool_behavior.baseline_host_status",
        return_value={
            "available": False,
            "status": "tool-unavailable-on-host",
            "reason": "missing jzlint CLI jar",
        },
    )
    def test_missing_jar_does_not_report_baseline_as_available(
        self,
        _baseline_status,
        _openssl_binary,
        _pkilint_binary,
    ):
        host = derive_tool_status(
            ROOT,
            java_path=None,
            jar_path=None,
            executable_path=None,
        )
        self.assertEqual(host["tool_status"]["jzlint-baseline"], "tool-unavailable-on-host")

    def test_absent_openssl_returns_host_unavailable_row(self):
        row = run_openssl_behavior(
            {
                "artifact_id": "a-cert",
                "artifact_type": "certificate",
                "path": "corpus/valid/openssl/openssl_mlkem768_ee_cert.pem",
                "validity": "valid",
            },
            ROOT,
            None,
        )
        self.assertEqual(row["behavior"], "tool-unavailable-on-host")

    def test_sanitize_tool_message_rewrites_workspace_path(self):
        artifact_path = ROOT / "corpus" / "mutated" / "der" / "der_mut_mlkem512_key_seed_short.pem"
        message = f"Could not parse {artifact_path}"

        sanitized = _sanitize_tool_message(message, root=ROOT, artifact_path=artifact_path)

        self.assertIn("corpus/mutated/der/der_mut_mlkem512_key_seed_short.pem", sanitized)
        self.assertNotIn(str(ROOT), sanitized)


if __name__ == "__main__":
    unittest.main()
