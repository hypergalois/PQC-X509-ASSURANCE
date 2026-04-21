# Experiments

Scripts in this directory reproduce the main artifact outputs and write them to
`../results` and, where appropriate, human-facing companion documents under
`../docs`.

## Core Replay Runners

These are the hard requirements for the local executable artifact path:

- `generate_corpus_openssl.sh`
- `generate_mutations_openssl.sh`
- `generate_der_mutations.sh`
- `run_extended.sh`
- `run_coverage.sh`
- `run_private_key_coverage.sh`
- `run_reference_workflow.sh`
- `run_operator_gate_packs.sh`
- `run_cross_tool_behavior.sh`
- `run_smoke_tests.sh`

## Operator-Facing Outputs

These runners generate the most operator-visible outputs:

- `run_reference_workflow.sh`: emits the owner/stage workflow summary as JSON
  plus the human-oriented `docs/reference-workflow.md`
- `run_operator_gate_packs.sh`: emits the gate-pack matrix, readiness summary,
  and `docs/operator-playbook.md`
- `run_cross_tool_behavior.sh`: emits the bounded cross-tool matrix and
  `docs/cross-tool-behavior.md`
- `run_real_world_appendix.sh`: refreshes the bounded appendix manifest,
  appendix notes, and nested appendix results

## Live Replay vs Frozen Fallback

Some scripts support optional live replay but can still reuse frozen outputs:

- `check_environment.sh`: inspection and status recording only; it should not
  block replay by default
- `run_baseline.sh`: live JZLint baseline tests plus CLI build when Maven is
  available
- `run_baseline_compare.sh`: falls back to frozen comparison outputs when live
  baseline replay is unavailable
- `run_real_world_appendix.sh`: regenerates appendix documentation from frozen
  metadata when the larger public-source snapshot is absent
- `replay_freeze.sh`: orchestrates the full replay and records whether baseline,
  bridge, and appendix paths were live or frozen

## Upstream-Dependent Helpers

These depend on vendored or restored upstream source snapshots:

- `prepare_third_party.sh`: reuses vendored snapshots or restores them from
  frozen archives when such archives are present
- `build_libcrux_import_check.sh`: builds the optional Rust importer bridge
- `extract_real_world_appendix.sh`: extracts the bounded public appendix from a
  local `pqc-certificates-main` snapshot
