from pathlib import Path
import unittest

from pqc_x509_assurance.run_extended import resolve_manifest_root


class ManifestRootResolutionTests(unittest.TestCase):
    def test_resolve_manifest_root_for_default_manifest(self):
        manifest = Path("/tmp/project/corpus/manifest.jsonl")
        records = [{"path": "corpus/valid/openssl/example.pem"}]
        self.assertEqual(
            resolve_manifest_root(manifest, records),
            Path("/tmp/project").resolve(),
        )

    def test_resolve_manifest_root_for_nested_appendix_manifest(self):
        manifest = Path("/tmp/project/corpus/appendix/manifest.jsonl")
        records = [{"path": "corpus/appendix/public_repo/ossl35/example.der"}]

        # The function will not find existing files in this synthetic setup, so
        # the fallback path should still land on the project root.
        self.assertEqual(
            resolve_manifest_root(manifest, records),
            Path("/tmp/project").resolve(),
        )


if __name__ == "__main__":
    unittest.main()
