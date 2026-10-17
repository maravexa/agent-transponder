#!/usr/bin/env bash
# Bootstrap verifier pinned to the official Sigstore linux/amd64 release digest.
set -euo pipefail
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
curl --fail --silent --show-error --location \
  https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-linux-amd64 \
  --output "$work/cosign"
(cd "$work" && echo '4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71  cosign' | sha256sum --check --strict)
mkdir -p "${RUNNER_TEMP:?}/verified-tools"
install -m 0755 "$work/cosign" "$RUNNER_TEMP/verified-tools/cosign"
printf '%s\n' "$RUNNER_TEMP/verified-tools" >> "${GITHUB_PATH:?}"
