# Third-Party Snapshots

This directory is the canonical home for upstream source snapshots that are
part of the repository's replay story.

## Included Upstreams

- `jzlint-main`: vendored JZLint baseline source snapshot used by
  `experiments/run_baseline.sh`, `experiments/run_baseline_compare.sh`, and the
  cross-tool matrix.
- `libcrux-main`: vendored libcrux source snapshot used to build the optional
  importer-side bridge at `tools/libcrux_import_check/`.

## Why They Live Here

These trees are not bundled for decoration. They are kept in-repo because the
artifact needs pinned upstream source inputs to support replay and bounded
cross-tool comparison without relying on moving network targets.

## Version-Control Boundary

Versioned here:

- upstream source trees needed for replay
- pinned files required to rebuild the optional importer bridge or the frozen
  baseline path

Never version here:

- `target/`
- `__pycache__/`
- `.pytest_cache/`

Build output and cache detritus must remain outside version control even when
the upstream source snapshot itself is intentionally vendored.
