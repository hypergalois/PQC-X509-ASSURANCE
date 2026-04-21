# Corpus

This repository ships two related corpus surfaces:

- a controlled corpus used for the executable regression path
- a bounded public appendix used to add limited external-validity evidence

## Controlled Corpus

The controlled corpus currently contains `48` artifacts:

- certificates: `17`
- SPKIs: `17`
- private-key containers: `14`
- valid artifacts: `21`
- invalid artifacts: `27`

The controlled tree is organized as follows:

- `valid/openssl/`: valid certificates, SPKIs, and private-key containers
  generated from the local OpenSSL-based path
- `mutated/openssl/`: negative certificate cases produced through issuance-time
  knobs
- `mutated/der/`: deterministic DER-level negative cases produced from frozen
  valid inputs
- `manifest.jsonl`: the controlled corpus manifest consumed by the local
  runners
- `manifest.example.jsonl`: the intended record shape for future corpus
  extensions

## Bounded Public Appendix

The public appendix currently contains `26` valid artifacts under
`appendix/public_repo/`, indexed by `appendix/manifest.jsonl`.

Its purpose is not to be an ecosystem census. It is a small, auditable external
validity layer that complements the controlled corpus with selected final
ML-KEM and ML-DSA public artifacts.

The appendix tree is organized as follows:

- `appendix/public_repo/`: extracted public appendix artifacts grouped by
  provider
- `appendix/manifest.jsonl`: bounded appendix manifest

## Manifest Fields

Each manifest line is a JSON object with at least:

- `artifact_id`
- `artifact_type`
- `path`
- `algorithm`
- `parameter_set`
- `source`
- `validity`
- `fault_family`
- `mutation`
- `mutation_family`
- `expected_detection`
- `stage`
- `sha256`

The appendix records add provider and selection metadata so the external corpus
can be replayed and audited without inflating the main controlled path.
