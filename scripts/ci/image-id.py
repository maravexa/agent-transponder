"""Read a single docker-archive image ID without extracting untrusted paths."""

import hashlib
import json
import sys
import tarfile

with tarfile.open(sys.argv[1]) as archive:
    manifests = json.load(archive.extractfile("manifest.json"))
    if len(manifests) != 1:
        raise ValueError("expected exactly one image")
    config = archive.extractfile(manifests[0]["Config"]).read()
    metadata = json.loads(config)
    if metadata["os"] != "linux" or metadata["architecture"] != sys.argv[2]:
        raise ValueError("unexpected image platform")
    print("sha256:" + hashlib.sha256(config).hexdigest())
