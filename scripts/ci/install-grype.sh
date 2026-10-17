#!/usr/bin/env bash
# Pinned official release; no remote installer execution. Linux/amd64 CI runner.
set -euo pipefail
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
version=0.120.1
base="https://github.com/anchore/grype/releases/download/v${version}"
for file in "grype_${version}_linux_amd64.tar.gz" "grype_${version}_checksums.txt" "grype_${version}_checksums.txt.sigstore.json"; do
  curl --fail --silent --show-error --location "$base/$file" --output "$work/$file"
done
(
  cd "$work"
  # Pins bind both executable and signed checksum manifest to the reviewed release.
  echo '0a9ee97ef5ae2ee953b0a80098105052e846cdbe319a57d808b519c33cd1343d  grype_0.120.1_linux_amd64.tar.gz' | sha256sum --check --strict
  echo 'c25b6095265b44fd9bbb9dbe76aca8daa394c5f0490793d2b52b16be4f5b71b1  grype_0.120.1_checksums.txt' | sha256sum --check --strict
  cosign verify-blob "grype_${version}_checksums.txt" \
    --bundle "grype_${version}_checksums.txt.sigstore.json" \
    --certificate-identity https://github.com/anchore/grype/.github/workflows/release.yaml@refs/heads/main \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
  grep " grype_${version}_linux_amd64.tar.gz$" "grype_${version}_checksums.txt" | sha256sum --check --strict
)
mkdir -p "${RUNNER_TEMP:?}/verified-tools"
tar -xzf "$work/grype_${version}_linux_amd64.tar.gz" -C "$RUNNER_TEMP/verified-tools" grype
printf '%s\n' "$RUNNER_TEMP/verified-tools" >> "${GITHUB_PATH:?}"
