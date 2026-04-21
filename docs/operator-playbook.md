# Operational Workflow Summary

Profile: `pkix-core`

This document summarizes the executable workflow for the current PKIX core repository snapshot.

- runtime boundary: runtime-consumer remains explicit as a boundary in pkix-core, but no active runtime requirements are executable in this repository snapshot.
- default CA mode: `deployable`
- reference assurance mode: `strict`
- operator reading rule: start from the gate-pack you own, then inspect the listed outputs for that mode

## CA certificate/profile gate

- gate_pack: `ca-certificate-profile`
- intended_owner: `ca-preissuance`
- stage: `certificate/profile`
- purpose: What the CA inspects in the certificate/profile gate before issuance, including keyUsage, signatureAlgorithm, and PKIX algorithm-policy checks.
- requirement_count: 5
- requirement_ids: MLDSA-CERT-KU-AT-LEAST-ONE-SIGNING-BIT, MLDSA-CERT-KU-NO-ENCIPHERMENT-OR-AGREEMENT, MLDSA-CERT-SIGNATURE-AID-PARAMS-ABSENT, MLDSA-PKIX-HASHML-FORBIDDEN, MLKEM-CERT-KU-KEYENCIPHERMENT-ONLY
- operator_question: what should `ca-preissuance` inspect before this gate passes?
- commands:
  - `deployable`:
    - `./experiments/run_extended.sh --mode deployable`
    - `./experiments/run_coverage.sh --mode deployable`
  - `strict`:
    - `./experiments/run_extended.sh --mode strict`
    - `./experiments/run_coverage.sh --mode strict`
- blocking_vs_warning:
  - deployable: blocks 5 requirements and warns on 0
  - strict: blocks 5 requirements and warns on 0
- inspect_outputs:
  - `deployable`:
    - `results/extended_registry_summary_deployable.json`
    - `results/policy_summary_deployable.json`
    - `results/certificate_spki_coverage_deployable.json`
    - `results/operator_readiness_summary.json`
  - `strict`:
    - `results/extended_registry_summary.json`
    - `results/policy_summary_strict.json`
    - `results/certificate_spki_coverage.json`
    - `results/operator_readiness_summary.json`

## CA SPKI/public-key gate

- gate_pack: `ca-spki-public-key`
- intended_owner: `ca-preissuance`
- stage: `SPKI/public-key`
- purpose: What the CA inspects in SubjectPublicKeyInfo before issuance, including AlgorithmIdentifier correctness and parameter-set sizing.
- requirement_count: 5
- requirement_ids: MLDSA-SPKI-AID-PARAMS-ABSENT, MLDSA-SPKI-PUBLIC-KEY-LENGTH, MLKEM-SPKI-AID-PARAMS-ABSENT, MLKEM-SPKI-ENCODE-DECODE-IDENTITY, MLKEM-SPKI-PUBLIC-KEY-LENGTH
- operator_question: what should `ca-preissuance` inspect before this gate passes?
- commands:
  - `deployable`:
    - `./experiments/run_extended.sh --mode deployable`
    - `./experiments/run_coverage.sh --mode deployable`
  - `strict`:
    - `./experiments/run_extended.sh --mode strict`
    - `./experiments/run_coverage.sh --mode strict`
- blocking_vs_warning:
  - deployable: blocks 4 requirements and warns on 1
  - strict: blocks 5 requirements and warns on 0
- inspect_outputs:
  - `deployable`:
    - `results/extended_registry_summary_deployable.json`
    - `results/policy_summary_deployable.json`
    - `results/certificate_spki_coverage_deployable.json`
    - `results/operator_gate_matrix.json`
  - `strict`:
    - `results/extended_registry_summary.json`
    - `results/policy_summary_strict.json`
    - `results/certificate_spki_coverage.json`
    - `results/operator_gate_matrix.json`

## Importer private-key gate

- gate_pack: `import-private-key`
- intended_owner: `artifact-importer`
- stage: `private-key-container/import`
- purpose: What the importer inspects before private-key acceptance, including CHOICE form, lengths, and seed/expanded consistency checks.
- requirement_count: 7
- requirement_ids: MLDSA-PRIVATE-BOTH-CONSISTENCY, MLDSA-PRIVATE-EXPANDED-LENGTH, MLDSA-PRIVATE-SEED-LENGTH, MLKEM-PRIVATE-BOTH-CONSISTENCY, MLKEM-PRIVATE-EXPANDED-HASH-CHECK, MLKEM-PRIVATE-EXPANDED-LENGTH, MLKEM-PRIVATE-SEED-LENGTH
- operator_question: what should `artifact-importer` inspect before this gate passes?
- commands:
  - `deployable`:
    - `./experiments/build_libcrux_import_check.sh`
    - `./experiments/run_extended.sh --mode deployable`
    - `./experiments/run_private_key_coverage.sh --mode deployable`
  - `strict`:
    - `./experiments/build_libcrux_import_check.sh`
    - `./experiments/run_extended.sh --mode strict`
    - `./experiments/run_private_key_coverage.sh --mode strict`
- blocking_vs_warning:
  - deployable: blocks 7 requirements and warns on 0
  - strict: blocks 7 requirements and warns on 0
- inspect_outputs:
  - `deployable`:
    - `results/extended_registry_summary_deployable.json`
    - `results/policy_summary_deployable.json`
    - `results/private_key_coverage_deployable.json`
    - `results/operator_gate_matrix.json`
  - `strict`:
    - `results/extended_registry_summary.json`
    - `results/policy_summary_strict.json`
    - `results/private_key_coverage.json`
    - `results/operator_gate_matrix.json`

## Notes

- CA guidance defaults to deployable mode so operator runs align with low-noise issuance gating.
- Strict mode remains the assurance-maximizing reference and should be used for deep audits or pre-release checks.
- The only non-blocking deployable requirement in the current registry is MLKEM-SPKI-ENCODE-DECODE-IDENTITY.
