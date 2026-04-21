import unittest

from pqc_x509_assurance.policy import (
    artifact_policy_context,
    evaluate_policy,
    policy_summary,
    requirement_action,
)


def requirement(
    requirement_id,
    *,
    algorithm="ML-DSA",
    stage="certificate/profile",
    artifact_type="certificate",
    owner="ca-preissuance",
    detector_kind="policy",
    normative_strength="must",
    constructibility="covered",
    mode_action=None,
):
    return {
        "id": requirement_id,
        "algorithm": algorithm,
        "artifact_type": artifact_type,
        "stage": stage,
        "profile": "pkix-core",
        "owner": owner,
        "detector_kind": detector_kind,
        "normative_strength": normative_strength,
        "constructibility": constructibility,
        "fault_family": "test",
        "source": ["TEST"],
        "source_locators": ["test locator"],
        "requirement": "test requirement",
        "severity": "error",
        "baseline_status": "test",
        "mutation_family": ["test-family"],
        "expected_detector": "detector.test",
        "mode_action": mode_action or {"deployable": "warn", "strict": "block"},
        "justification": "test justification",
    }


def finding(requirement_id, status="error"):
    return {
        "requirement_id": requirement_id,
        "status": status,
        "message": "test finding",
        "detector": "detector.test",
    }


class PolicyTests(unittest.TestCase):
    def test_requirement_action_reads_mode_specific_action(self):
        req = requirement("REQ-A", mode_action={"deployable": "warn", "strict": "block"})
        self.assertEqual(requirement_action(req, "deployable"), "warn")
        self.assertEqual(requirement_action(req, "strict"), "block")

    def test_evaluate_policy_splits_blocking_warning_and_ignored(self):
        requirements = [
            requirement("REQ-BLOCK", mode_action={"deployable": "warn", "strict": "block"}),
            requirement("REQ-WARN", mode_action={"deployable": "warn", "strict": "warn"}),
            requirement("REQ-IGNORE", mode_action={"deployable": "ignore", "strict": "ignore"}),
        ]
        record = {
            "artifact_id": "cert-1",
            "algorithm": "ML-DSA",
            "stage": "certificate/profile",
        }

        deployable = evaluate_policy(
            [
                finding("REQ-BLOCK"),
                finding("REQ-WARN"),
                finding("REQ-IGNORE"),
            ],
            record,
            requirements,
            mode="deployable",
            profile="pkix-core",
        )
        strict = evaluate_policy(
            [
                finding("REQ-BLOCK"),
                finding("REQ-WARN"),
                finding("REQ-IGNORE"),
            ],
            record,
            requirements,
            mode="strict",
            profile="pkix-core",
        )

        self.assertEqual(deployable["final_disposition"], "warn")
        self.assertEqual(deployable["blocking_requirement_ids"], [])
        self.assertEqual(deployable["warning_requirement_ids"], ["REQ-BLOCK", "REQ-WARN"])
        self.assertEqual(deployable["ignored_requirement_ids"], ["REQ-IGNORE"])

        self.assertEqual(strict["final_disposition"], "block")
        self.assertEqual(strict["blocking_requirement_ids"], ["REQ-BLOCK"])
        self.assertEqual(strict["warning_requirement_ids"], ["REQ-WARN"])
        self.assertEqual(strict["ignored_requirement_ids"], ["REQ-IGNORE"])
        self.assertEqual(strict["first_blocking_requirement"], "REQ-BLOCK")
        self.assertEqual(strict["first_warning_requirement"], "REQ-WARN")

    def test_artifact_policy_context_tracks_owner_and_applicable_ids(self):
        requirements = [
            requirement("REQ-A", owner="ca-preissuance"),
            requirement(
                "REQ-B",
                stage="private-key-container/import",
                artifact_type="private-key-container",
                owner="artifact-importer",
                detector_kind="import-crypto",
                algorithm="ML-KEM",
            ),
        ]

        context = artifact_policy_context(
            {"artifact_id": "cert-1", "algorithm": "ML-DSA", "stage": "certificate/profile"},
            requirements,
            profile="pkix-core",
        )
        self.assertEqual(context["owner"], "ca-preissuance")
        self.assertEqual(context["owners"], ["ca-preissuance"])
        self.assertEqual(context["applicable_requirement_ids"], ["REQ-A"])

    def test_policy_summary_counts_actions_for_mode(self):
        requirements = [
            requirement("REQ-BLOCK", mode_action={"deployable": "block", "strict": "block"}),
            requirement("REQ-WARN", mode_action={"deployable": "warn", "strict": "block"}),
            requirement("REQ-IGNORE", mode_action={"deployable": "ignore", "strict": "ignore"}),
        ]

        summary = policy_summary(requirements, profile="pkix-core", mode="deployable")
        self.assertEqual(summary["by_action"], {"block": 1, "ignore": 1, "warn": 1})
        self.assertEqual(summary["blocking_requirements"], ["REQ-BLOCK"])
        self.assertEqual(summary["warning_requirements"], ["REQ-WARN"])
        self.assertEqual(summary["ignored_requirements"], ["REQ-IGNORE"])


if __name__ == "__main__":
    unittest.main()
