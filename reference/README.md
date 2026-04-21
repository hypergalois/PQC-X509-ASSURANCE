# Reference Set

This directory stores the compact local reference set used by the executable
artifact and the paper narrative.

## Normative References

- `NIST.FIPS.203.pdf`: local copy of FIPS 203 for ML-KEM. Used by
  `requirements.json` and the registry-backed ML-KEM structural checks.
  Classification: normative.
- `NIST.FIPS.204.pdf`: local copy of FIPS 204 for ML-DSA. Used by
  `requirements.json` and the registry-backed ML-DSA structural checks.
  Classification: normative.
- `rfc9935.pdf`: local copy of RFC 9935 for ML-KEM in PKIX. Used by
  `requirements.json` and the certificate/SPKI/private-key registry entries.
  Classification: normative.
- `rfc9881.pdf`: local copy of RFC 9881 for ML-DSA in PKIX. Used by
  `requirements.json` and the certificate/SPKI/private-key registry entries.
  Classification: normative.

## Methodological Reference

- `2025-1241.pdf`: local paper/preprint snapshot kept as compact methodological
  context for the public repository snapshot. Classification: methodological.

## Upstream Policy

The public branch uses `third_party/` as the canonical representation for the
vendored upstream source snapshots needed by replay. To avoid duplicating the
same upstream material twice, this directory does not keep parallel ZIP copies
of the vendored `jzlint-main` and `libcrux-main` trees.
