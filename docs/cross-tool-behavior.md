# Cross-Tool Behavior

This document records tool behavior only. It does not treat parse acceptance as proof of conformance.

## Tool Status

- `extended-local`: `available`
- `jzlint-baseline`: `build-required`
- `openssl-cli`: `available-parse-only`
- `pkilint`: `tool-unavailable-on-host`

## Scope

- `artifact_count`: 57
- `certificate_count`: 25
- `private_key_count`: 32
- `source_sets`: {'controlled': 31, 'appendix': 26}

## Patterns

- OpenSSL parse acceptance diverges from local policy conformance on controlled invalid artifacts.
- Some baseline rows reflect host unavailability rather than baseline semantics or runtime fragility.

## Behavior Counts

### extended-local

- `accepted`: 27
- `rejected-semantic`: 5
- `rejected-structural`: 25

### jzlint-baseline

- `not-applicable`: 32
- `tool-unavailable-on-host`: 25

### openssl-cli

- `accepted`: 50
- `rejected-structural`: 7

### pkilint

- `not-applicable`: 32
- `tool-unavailable-on-host`: 25

## Notes

- This matrix is behavioral: acceptance and rejection reflect tool behavior, not proof of conformance.
- OpenSSL rows are parse/import signals only and should not be read as policy validation.
- JZLint baseline remains certificate-only and is marked not-applicable for private-key-container artifacts.
- Host unavailability is tracked separately from runtime fragility so the report does not over-claim semantic weakness.
