#!/usr/bin/env bash
set -euo pipefail
archive=${1:?docker archive required}
report_dir=${2:?report directory required}
mkdir -p "$report_dir"
rm -f "$(dirname "$archive")/image.sha256"
# Keep the existing critical threshold. Scanner/database failures also block.
grype "docker-archive:$archive" --fail-on critical -o json > "$report_dir/grype.json"
grype db status -o json > "$report_dir/database.json"
grype version > "$report_dir/scanner.txt"
# This is only produced after the scan succeeds; the publisher verifies it.
(
  cd "$(dirname "$archive")"
  sha256sum "$(basename "$archive")" > image.sha256
  # CI supplies BuildKit metadata; local Podman audits may not.
  if [[ -f metadata.json ]]; then sha256sum metadata.json >> image.sha256; fi
)
