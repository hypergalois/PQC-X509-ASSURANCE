import unittest
from pathlib import Path

from pqc_x509_assurance.real_world_appendix import APPENDIX_ARTIFACTS


ROOT = Path(__file__).resolve().parents[1]


class RealWorldAppendixTests(unittest.TestCase):
    def test_appendix_artifact_ids_and_outputs_are_unique(self):
        artifact_ids = [artifact.artifact_id for artifact in APPENDIX_ARTIFACTS]
        output_paths = [artifact.output_relpath for artifact in APPENDIX_ARTIFACTS]
        self.assertEqual(len(artifact_ids), len(set(artifact_ids)))
        self.assertEqual(len(output_paths), len(set(output_paths)))

    def test_appendix_stays_in_scope(self):
        self.assertTrue(APPENDIX_ARTIFACTS)
        self.assertLessEqual(
            {artifact.algorithm for artifact in APPENDIX_ARTIFACTS},
            {"ML-KEM", "ML-DSA"},
        )
        self.assertLessEqual(
            {artifact.artifact_type for artifact in APPENDIX_ARTIFACTS},
            {"certificate", "private-key-container"},
        )
        self.assertEqual(
            {artifact.provider for artifact in APPENDIX_ARTIFACTS},
            {"bc", "ossl35"},
        )

    def test_appendix_has_certificate_and_private_key_coverage(self):
        artifact_types = {artifact.artifact_type for artifact in APPENDIX_ARTIFACTS}
        stages = {artifact.stage for artifact in APPENDIX_ARTIFACTS}
        self.assertIn("certificate", artifact_types)
        self.assertIn("private-key-container", artifact_types)
        self.assertIn("certificate/profile", stages)
        self.assertIn("private-key-container/import", stages)

    def test_appendix_upgrade_stays_bounded_but_not_too_thin(self):
        self.assertGreaterEqual(len(APPENDIX_ARTIFACTS), 20)
        self.assertLessEqual(len(APPENDIX_ARTIFACTS), 30)

    def test_appendix_private_key_coverage_spans_all_parameter_sets(self):
        private_key_parameter_sets = {
            artifact.parameter_set
            for artifact in APPENDIX_ARTIFACTS
            if artifact.artifact_type == "private-key-container"
        }
        self.assertEqual(
            private_key_parameter_sets,
            {
                "ML-DSA-44",
                "ML-DSA-65",
                "ML-DSA-87",
                "ML-KEM-512",
                "ML-KEM-768",
                "ML-KEM-1024",
            },
        )

    def test_appendix_document_outputs_are_present(self):
        self.assertTrue((ROOT / "docs" / "real-world-appendix-ledger.md").exists())
        self.assertTrue((ROOT / "docs" / "appendix-selection-rationale.md").exists())


if __name__ == "__main__":
    unittest.main()
