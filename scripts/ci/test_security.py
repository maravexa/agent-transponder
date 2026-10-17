"""Offline CI security regression tests; fake executables never publish images."""

import hashlib
import io
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.bin = self.work / "bin"
        self.bin.mkdir()
        self.env = dict(
            os.environ,
            PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
            IMAGE="example.invalid/project/test",
            COMMIT="a" * 40,
            COMPONENT="test",
            TAGS="example.invalid/project/test:latest",
            CALL_LOG=str(self.work / "calls"),
        )
        (self.work / "scripts").symlink_to(ROOT / "scripts", target_is_directory=True)

    def executable(self, name, body):
        path = self.bin / name
        path.write_text("#!/bin/bash\nset -eu\n" + body)
        path.chmod(0o700)

    def run_script(self, name, *args):
        return subprocess.run(
            ["bash", str(ROOT / "scripts/ci" / name), *args],
            cwd=self.work,
            env=self.env,
            capture_output=True,
            text=True,
            check=False,
        )

    def archive(self, arch):
        directory = self.work / "images" / arch
        directory.mkdir(parents=True)
        config = json.dumps({"os": "linux", "architecture": arch}).encode()
        with tarfile.open(directory / "image.tar", "w") as archive:
            for name, data in [
                ("config.json", config),
                ("manifest.json", json.dumps([{"Config": "config.json"}]).encode()),
            ]:
                member = tarfile.TarInfo(name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        metadata = {
            "containerimage.config.digest": "sha256:"
            + hashlib.sha256(config).hexdigest(),
            "buildx.build.provenance": {
                "builder": {"id": "test"},
                "buildType": "test",
                "invocation": {},
            },
        }
        (directory / "metadata.json").write_text(json.dumps(metadata))
        checksum = hashlib.sha256((directory / "image.tar").read_bytes()).hexdigest()
        metadata_checksum = hashlib.sha256(
            (directory / "metadata.json").read_bytes()
        ).hexdigest()
        (directory / "image.sha256").write_text(
            checksum + "  image.tar\n" + metadata_checksum + "  metadata.json\n"
        )
        return directory

    def test_tampered_second_archive_prevents_all_publication(self):
        self.archive("amd64")
        directory = self.archive("arm64")
        with (directory / "image.tar").open("ab") as stream:
            stream.write(b"tampered")
        self.executable("docker", 'echo docker >> "$CALL_LOG"\n')
        result = self.run_script("publish-images.sh")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse((self.work / "calls").exists())

    def test_tampered_metadata_prevents_all_publication(self):
        self.archive("amd64")
        directory = self.archive("arm64")
        metadata = directory / "metadata.json"
        metadata.write_text(metadata.read_text() + "\n")
        self.executable("docker", 'echo docker >> "$CALL_LOG"')
        result = self.run_script("publish-images.sh")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.work / "calls").exists())

    def test_missing_provenance_prevents_publication(self):
        self.archive("amd64")
        directory = self.archive("arm64")
        (directory / "metadata.json").unlink()
        self.executable("docker", 'echo docker >> "$CALL_LOG"\n')
        result = self.run_script("publish-images.sh")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.work / "calls").exists())

    def test_provenance_for_different_image_rejected(self):
        directory = self.archive("amd64")
        result = subprocess.run(
            [
                "python3",
                str(ROOT / "scripts/ci/prepare-provenance.py"),
                str(directory / "metadata.json"),
                "sha256:" + "0" * 64,
                str(directory / "provenance.json"),
            ],
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((directory / "provenance.json").exists())

    def test_wrong_architecture_rejected(self):
        directory = self.archive("amd64")
        result = subprocess.run(
            [
                "python3",
                str(ROOT / "scripts/ci/image-id.py"),
                str(directory / "image.tar"),
                "arm64",
            ],
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_scan_failure_never_creates_publication_receipt(self):
        directory = self.archive("amd64")
        (directory / "image.sha256").unlink()
        self.executable(
            "grype", 'echo \'{"matches": [{"severity": "Critical"}]}\'\nexit 2\n'
        )
        result = self.run_script(
            "scan-image.sh", str(directory / "image.tar"), str(self.work / "reports")
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((directory / "image.sha256").exists())
        self.assertTrue((self.work / "reports/grype.json").exists())

    def test_scanner_error_blocks_like_vulnerability(self):
        directory = self.archive("amd64")
        (directory / "image.sha256").unlink()
        self.executable("grype", "exit 1\n")
        result = self.run_script(
            "scan-image.sh", str(directory / "image.tar"), str(self.work / "reports")
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((directory / "image.sha256").exists())

    def test_corrupt_scanner_download_not_executed(self):
        self.executable(
            "curl",
            'while [[ "$#" -gt 0 ]]; do if [[ "$1" == --output ]]; then echo corrupt > "$2"; exit; fi; shift; done\n',
        )
        self.executable("cosign", 'echo called >> "$CALL_LOG"\n')
        self.env.update(RUNNER_TEMP=str(self.work), GITHUB_PATH=str(self.work / "path"))
        result = self.run_script("install-grype.sh")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.work / "verified-tools/grype").exists())
        self.assertFalse((self.work / "calls").exists())

    def test_publisher_uses_scanned_ids_without_rebuild(self):
        ids = []
        for arch in ["amd64", "arm64"]:
            directory = self.archive(arch)
            result = subprocess.run(
                [
                    "python3",
                    str(ROOT / "scripts/ci/image-id.py"),
                    str(directory / "image.tar"),
                    arch,
                ],
                capture_output=True,
                text=True,
                check=True,
            )
            ids.append(result.stdout.strip())
        self.executable(
            "docker",
            """echo "docker $*" >> "$CALL_LOG"
if [[ "$1" == push ]]; then
  printf 'tag: digest: sha256:%064d size: 123\\n' 0
  if [[ "$2" == *-amd64 ]]; then cat images/amd64/image.id > current.id; else cat images/arm64/image.id > current.id; fi
elif [[ "$*" == *"imagetools inspect"* ]]; then
  printf '{"config":{"digest":"%s"}}\\n' "$(cat current.id)"
elif [[ "$*" == *"imagetools create"* ]]; then
  printf '{"containerimage.descriptor":{"digest":"sha256:%064d"}}\\n' 0 > index-metadata.json
fi
""",
        )
        for name in ["cosign", "syft"]:
            self.executable(name, 'echo "' + name + ' $*" >> "$CALL_LOG"\n')
        result = self.run_script("publish-images.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = (self.work / "calls").read_text()
        for image_id in ids:
            self.assertIn("docker tag " + image_id, calls)
        self.assertNotIn("docker build ", calls)
        self.assertEqual(calls.count("docker push "), 2)
        for line in calls.splitlines():
            if "imagetools inspect" in line:
                self.assertIn("@sha256:", line)
            if "imagetools create" in line:
                self.assertEqual(line.count("@sha256:"), 2)

    def test_invalid_tag_prevents_all_registry_writes(self):
        self.env["TAGS"] = self.env["IMAGE"] + ":bad tag"
        self.executable("docker", 'echo docker >> "$CALL_LOG"')
        result = self.run_script("publish-images.sh")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.work / "calls").exists())

    def test_registry_config_mismatch_never_signed(self):
        for arch in ["amd64", "arm64"]:
            self.archive(arch)
        self.executable(
            "docker",
            """
if [[ "$1" == push ]]; then printf 'tag: digest: sha256:%064d size: 123\\n' 0;
elif [[ "$*" == *"imagetools inspect"* ]]; then echo '{"config":{"digest":"wrong"}}'; fi
""",
        )
        self.executable("cosign", 'echo signed >> "$CALL_LOG"')
        result = self.run_script("publish-images.sh")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.work / "calls").exists())

    def test_tag_is_data_not_shell(self):
        marker = self.work / "injected"
        self.env["RELEASE_TAG"] = (
            "v1; touch " + str(marker) + ";$(touch " + str(marker) + ")"
        )
        self.executable("gh", 'printf "%s\\n" "$@" > "$CALL_LOG"\n')
        workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
        step = workflow["jobs"]["release"]["steps"][-1]
        result = subprocess.run(
            ["bash", "-eu", "-c", step["run"]],
            cwd=self.work,
            env=self.env,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertFalse(marker.exists())
        self.assertIn(
            self.env["RELEASE_TAG"], (self.work / "calls").read_text().splitlines()
        )

    def test_workflow_security_boundaries(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
        jobs = workflow["jobs"]
        self.assertEqual(jobs["build-images"]["permissions"], {"contents": "read"})
        self.assertEqual(jobs["publish-images"]["if"], "github.event_name == 'push'")
        self.assertEqual(jobs["publish-images"]["needs"], ["build-images"])
        self.assertEqual(jobs["release"]["needs"], ["publish-images"])
        self.assertNotIn("packages", jobs["release"]["permissions"])
        self.assertFalse(
            any(
                "docker/login-action" in step.get("uses", "")
                for step in jobs["release"]["steps"]
            )
        )
        self.assertNotIn(
            "extra_files",
            yaml.safe_load((ROOT / ".goreleaser.yml").read_text())["release"],
        )
        self.assertNotIn(
            "dockers", yaml.safe_load((ROOT / ".goreleaser.yml").read_text())
        )
        for job in jobs.values():
            for step in job.get("steps", []):
                if "uses" in step:
                    self.assertRegex(step["uses"], r"@[0-9a-f]{40}$")
                if "run" in step:
                    self.assertNotIn("${{ github.", step["run"])
        self.assertIn(
            "--fail-on critical", (ROOT / "scripts/ci/scan-image.sh").read_text()
        )


if __name__ == "__main__":
    unittest.main()
