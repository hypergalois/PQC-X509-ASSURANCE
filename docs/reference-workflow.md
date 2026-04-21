# Reference Workflow

Profile: `pkix-core`

This workflow packages the current artifact as an operational recipe by owner and stage.

## Shared Outputs

- `policy_matrix`: `results/policy_matrix.csv`
- `stage_owner_summary`: `results/stage_owner_summary.json`
- `baseline_compare`: `results/baseline_vs_extended_certificate_report.json`

## Mode Outputs

### strict

- `extended_summary`: `results/extended_registry_summary.json`
- `policy_summary`: `results/policy_summary_strict.json`
- `certificate_spki_coverage`: `results/certificate_spki_coverage.json`
- `private_key_coverage`: `results/private_key_coverage.json`

### deployable

- `extended_summary`: `results/extended_registry_summary_deployable.json`
- `policy_summary`: `results/policy_summary_deployable.json`
- `certificate_spki_coverage`: `results/certificate_spki_coverage_deployable.json`
- `private_key_coverage`: `results/private_key_coverage_deployable.json`

## Artifact importer gate

- owner: `artifact-importer`
- status: `active`
- requirement_count: 7
- operator_focus: What the importer validates before accepting a private-key container for use.
- commands:
  - `strict`:
    - `./experiments/build_libcrux_import_check.sh`
    - `./experiments/run_extended.sh --mode strict`
    - `./experiments/run_private_key_coverage.sh --mode strict`
  - `deployable`:
    - `./experiments/build_libcrux_import_check.sh`
    - `./experiments/run_extended.sh --mode deployable`
    - `./experiments/run_private_key_coverage.sh --mode deployable`
- stages:
  - `private-key-container/import`: Validate imported private-key containers before use.
    - requirements: 7
    - requirement_ids: MLDSA-PRIVATE-BOTH-CONSISTENCY, MLDSA-PRIVATE-EXPANDED-LENGTH, MLDSA-PRIVATE-SEED-LENGTH, MLKEM-PRIVATE-BOTH-CONSISTENCY, MLKEM-PRIVATE-EXPANDED-HASH-CHECK, MLKEM-PRIVATE-EXPANDED-LENGTH, MLKEM-PRIVATE-SEED-LENGTH
    - strict actions: {"block": 7}
    - deployable actions: {"block": 7}

## CA pre-issuance gate

- owner: `ca-preissuance`
- status: `active`
- requirement_count: 10
- operator_focus: What the CA inspects before issuance across certificate/profile and SPKI/public-key gates.
- commands:
  - `strict`:
    - `./experiments/run_extended.sh --mode strict`
    - `./experiments/run_coverage.sh --mode strict`
  - `deployable`:
    - `./experiments/run_extended.sh --mode deployable`
    - `./experiments/run_coverage.sh --mode deployable`
- stages:
  - `SPKI/public-key`: Validate public-key structure and profile before issuance.
    - requirements: 5
    - requirement_ids: MLDSA-SPKI-AID-PARAMS-ABSENT, MLDSA-SPKI-PUBLIC-KEY-LENGTH, MLKEM-SPKI-AID-PARAMS-ABSENT, MLKEM-SPKI-ENCODE-DECODE-IDENTITY, MLKEM-SPKI-PUBLIC-KEY-LENGTH
    - strict actions: {"block": 5}
    - deployable actions: {"block": 4, "warn": 1}
  - `certificate/profile`: Validate certificate semantics and PKIX policy before issuance.
    - requirements: 5
    - requirement_ids: MLDSA-CERT-KU-AT-LEAST-ONE-SIGNING-BIT, MLDSA-CERT-KU-NO-ENCIPHERMENT-OR-AGREEMENT, MLDSA-CERT-SIGNATURE-AID-PARAMS-ABSENT, MLDSA-PKIX-HASHML-FORBIDDEN, MLKEM-CERT-KU-KEYENCIPHERMENT-ONLY
    - strict actions: {"block": 5}
    - deployable actions: {"block": 5}

## Runtime consumer boundary

- owner: `runtime-consumer`
- status: `out-of-scope`
- requirement_count: 0
- operator_focus: Explicit boundary information for runtime consumers that remain outside executable scope.
- note: No active requirements are currently assigned to runtime-consumer in pkix-core; runtime remains outside the executable scope of this artifact.
- commands:
  - `strict`: none
  - `deployable`: none
- stages:
  - none

## Notes

- Baseline comparison remains supporting evidence, not the primary workflow output.
- CA pre-issuance owns certificate/profile and SPKI/public-key gates in pkix-core.
- Artifact importer owns private-key-container/import checks in pkix-core.
