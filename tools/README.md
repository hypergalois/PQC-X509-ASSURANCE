# Tools

This directory contains small bridge tooling that supports parts of the replay
path without expanding the main Python codebase.

- `libcrux_import_check/` is a minimal Rust bridge used only for
  importer-side seed/expanded consistency checks against `libcrux`.
- its source is versioned
- its `target/` build output is intentionally excluded from version control
