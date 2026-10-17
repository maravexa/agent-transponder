#!/usr/bin/env bash
# Executed only in the push-only publisher after every architecture passed scan.
set -euo pipefail
: "${IMAGE:?}" "${COMMIT:?}" "${TAGS:?}"
[[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]] || exit 1
refs=()
declare -A digests
# Reject malformed destination tags before any registry write.
while IFS= read -r tag; do
  [[ -n "$tag" ]] || continue
  [[ "$tag" == "$IMAGE:"* ]] || exit 1
  suffix=${tag#"$IMAGE:"}
  [[ "$suffix" =~ ^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127}$ ]] || exit 1
done <<< "$TAGS"
# Validate both artifacts before the first registry write.
for arch in amd64 arm64; do
  (cd "images/$arch" && sha256sum --check --strict image.sha256)
  python3 scripts/ci/image-id.py "images/$arch/image.tar" "$arch" > "images/$arch/image.id"
  python3 scripts/ci/prepare-provenance.py "images/$arch/metadata.json" "$(cat "images/$arch/image.id")" "images/$arch/provenance.json" > "images/$arch/provenance.type"
done
for arch in amd64 arm64; do
  dir="images/$arch"
  # Read the ID from the archive; tag exactly that image after loading it.
  image_id=$(cat "$dir/image.id")
  docker load --input "$dir/image.tar"
  ref="$IMAGE:sha-$COMMIT-$arch"
  docker tag "$image_id" "$ref"
  docker push "$ref" | tee "$dir/push.log"
  digest=$(sed -nE 's/^.*digest: (sha256:[0-9a-f]{64}) size: [0-9]+.*$/\1/p' "$dir/push.log")
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || exit 1
  # Resolve immutable content and confirm that the registry manifest contains
  # the config scanned locally. Never re-resolve an architecture tag.
  config=$(docker buildx imagetools inspect "$IMAGE@$digest" --raw | jq -er '.config.digest')
  [[ "$config" == "$image_id" ]] || exit 1
  digests[$arch]=$digest
  refs+=("$IMAGE@$digest")
done
mkdir -p sbom
while IFS= read -r tag; do
  [[ -n "$tag" ]] || continue
  [[ "$tag" == "$IMAGE:"* ]] || { echo 'Unexpected image tag' >&2; exit 1; }
  docker buildx imagetools create --metadata-file index-metadata.json --tag "$tag" "${refs[@]}"
  digest=$(jq -er '.["containerimage.descriptor"].digest' index-metadata.json)
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || exit 1
  cosign sign --yes "$IMAGE@$digest"
done <<< "$TAGS"
# SBOMs describe the actual published architecture manifests, not a rebuild.
for arch in amd64 arm64; do
  digest=${digests[$arch]}
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || exit 1
  cosign sign --yes "$IMAGE@$digest"
  cosign attest --yes --predicate "images/$arch/provenance.json" --type "$(cat "images/$arch/provenance.type")" "$IMAGE@$digest"
  syft "$IMAGE@$digest" -o "spdx-json=sbom/${COMPONENT:?}-$arch.spdx.json" -o "cyclonedx-json=sbom/$COMPONENT-$arch.cdx.json"
  cosign attest --yes --predicate "sbom/$COMPONENT-$arch.spdx.json" --type spdxjson "$IMAGE@$digest"
done
