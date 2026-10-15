"""Compare bounded saved evidence. A file hash is integrity, not authenticity."""

import hashlib
import json
from pathlib import Path

from .target import parse_target


def load_report(path):
    path = Path(path)
    if path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError("Report exceeds 4 MiB")
    raw = path.read_bytes()
    report = json.loads(raw)
    stack = [(report, 0)]
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if depth > 64 or nodes > 50000:
            raise ValueError("Report structure limit exceeded")
        if isinstance(value, dict):
            stack.extend((v, depth + 1) for v in value.values())
        elif isinstance(value, list):
            stack.extend((v, depth + 1) for v in value)
    if not isinstance(report, dict) or report.get("schema") != "t3-evidence/1":
        raise ValueError("Expected a t3-evidence/1 report")
    if not isinstance(report.get("target"), dict) or not isinstance(report.get("evidence"), list):
        raise ValueError("Malformed report structure")
    canonical = parse_target(report["target"].get("url"))
    if canonical.host != report["target"].get("host") or canonical.url != report["target"]["url"]:
        raise ValueError("Report target host disagrees with URL")
    if len(report["evidence"]) > 50:
        raise ValueError("Too many evidence entries")
    if not all(
        isinstance(x, dict) and isinstance(x.get("id"), str) and isinstance(x.get("status"), str)
        for x in report["evidence"]
    ):
        raise ValueError("Malformed evidence entry")
    if len({x["id"] for x in report["evidence"]}) != len(report["evidence"]):
        raise ValueError("Duplicate evidence IDs")
    return report, hashlib.sha256(raw).hexdigest()


def compare_reports(before, after):
    if before["target"]["url"] != after["target"]["url"]:
        raise ValueError("Compare reports for the exact same normalized URL")
    left, right = ({x["id"]: x for x in report["evidence"]} for report in (before, after))
    changes = []
    for identifier in sorted(left.keys() | right.keys()):
        old, new = left.get(identifier), right.get(identifier)

        # Collection timestamps alone must not masquerade as changed evidence.
        def stable(value):
            if isinstance(value, dict):
                return {k: stable(v) for k, v in value.items() if k != "collected_at"}
            if isinstance(value, list):
                return [stable(v) for v in value]
            return value

        old_fact, new_fact = stable(old), stable(new)
        if old_fact != new_fact:
            changes.append(dict(probe=identifier, before=old_fact, after=new_fact))
    return dict(
        schema="t3-comparison/1",
        target=before["target"]["url"],
        before_started_at=before.get("started_at"),
        after_started_at=after.get("started_at"),
        scope_changed=before.get("scope") != after.get("scope"),
        changes=changes,
        interpretation="Observed report differences only; no phishing verdict or source authenticity proof.",
    )
