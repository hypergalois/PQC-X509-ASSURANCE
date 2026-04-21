import unittest

from pathlib import Path

from pqc_x509_assurance.reference_workflow import (
    build_reference_workflow,
    render_reference_workflow_markdown,
)


ROOT = Path(__file__).resolve().parents[1]


class ReferenceWorkflowTests(unittest.TestCase):
    def test_reference_workflow_includes_all_policy_owners(self):
        workflow = build_reference_workflow(ROOT / "requirements.json", profile="pkix-core")
        owners = {entry["owner"]: entry for entry in workflow["owners"]}

        self.assertEqual(set(owners), {"artifact-importer", "ca-preissuance", "runtime-consumer"})
        self.assertEqual(owners["runtime-consumer"]["status"], "out-of-scope")
        self.assertEqual(owners["runtime-consumer"]["stages"], [])

    def test_ca_preissuance_workflow_captures_warning_stage_split(self):
        workflow = build_reference_workflow(ROOT / "requirements.json", profile="pkix-core")
        owners = {entry["owner"]: entry for entry in workflow["owners"]}
        ca = owners["ca-preissuance"]
        stages = {entry["stage"]: entry for entry in ca["stages"]}

        self.assertIn("SPKI/public-key", stages)
        self.assertIn("certificate/profile", stages)
        self.assertEqual(
            stages["SPKI/public-key"]["actions"]["deployable"].get("warn"),
            1,
        )
        self.assertIn(
            "MLKEM-SPKI-ENCODE-DECODE-IDENTITY",
            ca["modes"]["deployable"]["warning_requirements"],
        )

    def test_reference_workflow_markdown_preserves_owner_and_importer_commands(self):
        workflow = build_reference_workflow(ROOT / "requirements.json", profile="pkix-core")
        markdown = render_reference_workflow_markdown(workflow)
        self.assertIn("## CA pre-issuance gate", markdown)
        self.assertIn("## Artifact importer gate", markdown)
        self.assertIn("## Runtime consumer boundary", markdown)
        self.assertIn("`certificate/profile`", markdown)
        self.assertIn("`SPKI/public-key`", markdown)
        self.assertIn("./experiments/build_libcrux_import_check.sh", markdown)
        self.assertIn("./experiments/run_private_key_coverage.sh --mode strict", markdown)


if __name__ == "__main__":
    unittest.main()
