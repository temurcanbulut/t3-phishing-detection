import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "T3-Phishing-Detection"))
from t3core.compare import compare_reports, load_report


class ComparisonTests(unittest.TestCase):
    def setUp(self):
        self.report = dict(
            schema="t3-evidence/1",
            target=dict(url="https://example.com/", host="example.com"),
            scope=dict(active=True),
            started_at="2026-10-15T00:00:00Z",
            evidence=[
                dict(
                    id="http",
                    status="observed",
                    data=[dict(body_sha256="a", collected_at="one")],
                    collected_at="one",
                )
            ],
        )

    def test_only_collection_time_changes_are_ignored(self):
        after = copy.deepcopy(self.report)
        after["evidence"][0]["collected_at"] = "two"
        after["evidence"][0]["data"][0]["collected_at"] = "two"
        self.assertEqual(compare_reports(self.report, after)["changes"], [])

    def test_body_and_status_changes_are_retained(self):
        after = copy.deepcopy(self.report)
        after["evidence"][0]["data"][0]["body_sha256"] = "b"
        after["evidence"][0]["status"] = "limited"
        result = compare_reports(self.report, after)
        self.assertEqual(result["changes"][0]["probe"], "http")
        self.assertEqual(result["changes"][0]["after"]["status"], "limited")

    def test_scope_changes_are_explicit(self):
        after = copy.deepcopy(self.report)
        after["scope"]["active"] = False
        self.assertTrue(compare_reports(self.report, after)["scope_changed"])

    def test_different_targets_cannot_be_compared(self):
        after = copy.deepcopy(self.report)
        after["target"]["url"] = "https://example.com/path"
        with self.assertRaises(ValueError):
            compare_reports(self.report, after)

    def test_file_hash_and_duplicate_evidence_validation(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "report.json"
            path.write_text(json.dumps(self.report))
            loaded, digest = load_report(path)
            self.assertEqual(loaded, self.report)
            self.assertEqual(len(digest), 64)
            self.report["evidence"] *= 2
            path.write_text(json.dumps(self.report))
            with self.assertRaises(ValueError):
                load_report(path)

    def test_mismatched_host_and_deep_structure_are_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "report.json"
            after = copy.deepcopy(self.report)
            after["target"]["host"] = "other.example"
            path.write_text(json.dumps(after))
            with self.assertRaises(ValueError):
                load_report(path)
            nested = "x"
            for _ in range(70):
                nested = [nested]
            self.report["evidence"][0]["data"] = nested
            path.write_text(json.dumps(self.report))
            with self.assertRaises(ValueError):
                load_report(path)
