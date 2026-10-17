# Image security gate


CI builds Docker archives for linux/amd64 and linux/arm64 without registry or OIDC
write permissions. Pinned Grype scans those archives at the existing **critical**
threshold; vulnerability, download, signature, database and scanner errors block
publication. The publisher runs only for pushes and depends on all architecture
scans. It validates archive checksums/platforms before any registry writes, loads
and tags the scanned image IDs, and publishes multiarchitecture indexes. It never
rebuilds images. GoReleaser publishes binary archives only, preventing a second,
unscanned image path. Image signatures and architecture-specific SBOM attestations
remain enabled. Docker archive transport cannot embed BuildKit attestations, so
CI retains BuildKit provenance metadata alongside each archive, verifies its
image config digest, and signs that provenance against the published architecture
digest. Missing or unsupported provenance blocks publication. This transfer needs
hosted Buildx validation before rollout; local Podman tests cannot exercise the
GitHub build-action metadata output.

Grype v0.120.1 is bound to a reviewed archive/manifest SHA256 and its checksum
manifest's Sigstore signature, exact Anchore release-workflow identity, and GitHub
OIDC issuer. Cosign v3.1.3 is bootstrapped from the official Sigstore release using
a pinned SHA256. Binary releases retain Cosign v2.5.2 via the pinned installer
action and its embedded checksums, preserving the existing detached signature
interface. Updating either scanner tool requires reviewing the new official release
and replacing the pins. All workflow actions are pinned to upstream commit SHAs.

Standalone gosec and Bandit remain report-only; Semgrep findings remain report-only.
Golangci-lint still enforces high-severity gosec findings at medium confidence.
Changing these thresholds requires an explicit gate-policy decision and baseline
triage; this hardening adds no suppressions and does not reinterpret a green report
job as proof of no findings. Run `python3 scripts/ci/test_security.py` (PyYAML) to
exercise publication guards and offline failure paths. PRs never get publisher
credentials and no `pull_request_target` workflow is used.

Publication uses Docker push's returned architecture digests and verifies each
registry manifest config against the scanned archive before indexing or signing.
Index creation uses those immutable references; its metadata file supplies the
index digest for signing (no mutable-tag lookup). See the official
[Buildx metadata contract](https://docs.docker.com/reference/cli/docker/buildx/imagetools/create/#write-create-result-metadata-to-a-file---metadata-file).
The binary release job has no package-write permission or registry login. Image
SBOMs are attached after download; GoReleaser generates its own binary SBOMs.

Limits: artifact SHA256 receipts detect transfer corruption, not a malicious
build job capable of changing both artifact and receipt. BuildKit metadata is
builder-supplied provenance, subsequently signed by the publisher; it is not an
independent hermetic build attestation. PR builds have no publication credentials;
push publication trusts the checked-out workflow and scripts. Base images, Buildx
and some report-only SAST tools/rules remain floating; action SHA pinning does not
pin every executable or ruleset. No claim of full reproducibility is made.
Publication is non-atomic: a failure can leave uploaded architecture tags or
unsigned indexes. Consumers must verify signatures and required attestations,
and hosted validation must cover Buildx metadata, registry config binding, both
platforms, signatures, provenance and SBOM attachment before publication readiness
can be declared. This local review does not authorize a push or release.
