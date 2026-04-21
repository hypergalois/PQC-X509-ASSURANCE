import unittest

from pathlib import Path

from pqc_x509_assurance.operator_gate_packs import build_operator_gate_pack_report
from pqc_x509_assurance.requirements import load_registry, requirements


ROOT = Path(__file__).resolve().parents[1]


class OperatorGatePackTests(unittest.TestCase):
    def test_every_requirement_maps_to_exactly_one_gate_pack(self):
        registry = load_registry(ROOT / "requirements.json")
        records = requirements(registry)
        gate_packs = [record["gate_pack"] for record in records]

        self.assertEqual(len(gate_packs), len(records))
        self.assertEqual(gate_packs.count("ca-certificate-profile"), 5)
        self.assertEqual(gate_packs.count("ca-spki-public-key"), 5)
        self.assertEqual(gate_packs.count("import-private-key"), 7)

    def test_gate_pack_membership_matches_owner_and_stage(self):
        report = build_operator_gate_pack_report(ROOT / "requirements.json", profile="pkix-core")
        packs = {entry["gate_pack"]: entry for entry in report["gate_packs"]}

        self.assertEqual(packs["ca-certificate-profile"]["owner"], "ca-preissuance")
        self.assertEqual(packs["ca-certificate-profile"]["stage"], "certificate/profile")
        self.assertEqual(packs["ca-spki-public-key"]["owner"], "ca-preissuance")
        self.assertEqual(packs["ca-spki-public-key"]["stage"], "SPKI/public-key")
        self.assertEqual(packs["import-private-key"]["owner"], "artifact-importer")
        self.assertEqual(
            packs["import-private-key"]["stage"],
            "private-key-container/import",
        )

    def test_deployable_warning_only_surfaces_for_mlkem_encode_decode_identity(self):
        report = build_operator_gate_pack_report(ROOT / "requirements.json", profile="pkix-core")
        packs = {entry["gate_pack"]: entry for entry in report["gate_packs"]}

        self.assertEqual(
            packs["ca-spki-public-key"]["deployable"]["warning_requirement_ids"],
            ["MLKEM-SPKI-ENCODE-DECODE-IDENTITY"],
        )
        self.assertEqual(
            packs["ca-certificate-profile"]["deployable"]["warning_requirement_ids"],
            [],
        )
        self.assertEqual(
            packs["import-private-key"]["deployable"]["warning_requirement_ids"],
            [],
        )


if __name__ == "__main__":
    unittest.main()
