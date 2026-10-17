"""Bind retained BuildKit provenance to the scanned image config before signing."""

import json
import sys
from pathlib import Path

metadata = json.loads(Path(sys.argv[1]).read_text())
if metadata.get("containerimage.config.digest") != sys.argv[2]:
    raise ValueError("build metadata does not describe the scanned image")
predicate = metadata.get("buildx.build.provenance")
if not isinstance(predicate, dict) or not predicate:
    raise ValueError("missing BuildKit provenance")
if "buildDefinition" in predicate and "runDetails" in predicate:
    kind = "https://slsa.dev/provenance/v1"
elif "builder" in predicate and "buildType" in predicate and "invocation" in predicate:
    kind = "https://slsa.dev/provenance/v0.2"
else:
    raise ValueError("unsupported BuildKit provenance format")
Path(sys.argv[3]).write_text(json.dumps(predicate))
print(kind)
