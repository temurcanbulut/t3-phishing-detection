"""Record the installed runtime dependency closure used for this audit."""

from importlib.metadata import distribution
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

root = Path(__file__).resolve().parents[1]
pending = [
    Requirement(line).name
    for line in (root / "requirements.txt").read_text().splitlines()
    if line and not line.startswith("#")
]
versions = {}
while pending:
    name = canonicalize_name(pending.pop())
    if name in versions:
        continue
    installed = distribution(name)
    versions[name] = installed.version
    for text in installed.requires or []:
        requirement = Requirement(text)
        if requirement.marker is None or requirement.marker.evaluate():
            pending.append(requirement.name)
header = "# Audited runtime snapshot: Windows Python 3.12, 2026-10-15.\n# Regenerate from a tested environment with python tools/snapshot_runtime.py.\n"
(root / "requirements-audited.txt").write_text(
    header + "\n".join(f"{k}=={v}" for k, v in sorted(versions.items())) + "\n", encoding="utf-8"
)
print(f"Recorded {len(versions)} runtime distributions")
