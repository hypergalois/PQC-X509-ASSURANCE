# Appendix Corpus Scope

The purpose of the public appendix is to add a small,reproducible external-validity layer to the controlled corpus without turning
the repository into an ecosystem census.

## Selection Priorities

- Keep scope fixed to final ML-KEM and pure ML-DSA only.
- Preserve two-provider evidence (`ossl35`, `bc`).
- Strengthen importer-facing external validity with more private-key containers.
- Cover low/default/high parameter sets across both algorithm families.

## Resulting Coverage

- artifact_count: 26
- providers: bc, ossl35
- artifact surfaces: certificate, private-key-container
- parameter_sets: ML-DSA-44, ML-DSA-65, ML-DSA-87, ML-KEM-1024, ML-KEM-512, ML-KEM-768
- private-key parameter coverage: ML-DSA-44, ML-DSA-65, ML-DSA-87, ML-KEM-1024, ML-KEM-512, ML-KEM-768
