import pathlib
import socket
import ssl
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(
    0, str(pathlib.Path(__file__).resolve().parents[1] / "T3-Phishing-Detection")
)
import analysis
from app import app, analysis_slots


def dns(*addresses):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443)) for ip in addresses]


class TargetTests(unittest.TestCase):
    def test_preserves_path_query_but_not_fragment(self):
        target = analysis.parse_target("HTTPS://Example.COM:443/a/b?x=1&y=2#private")
        self.assertEqual(target.url, "https://example.com/a/b?x=1&y=2")

    def test_bare_and_international_domains(self):
        self.assertEqual(
            analysis.parse_target("example.com").url, "https://example.com/"
        )
        self.assertEqual(analysis.parse_target("bücher.de").host, "xn--bcher-kva.de")

    def test_invalid_targets(self):
        for value in (
            None,
            "",
            [],
            "https://",
            "ftp://example.com",
            "https://a:b@example.com",
            "https://example.com:8080",
            "https://example.com\\@localhost",
            "example.com\n/path",
            "-bad.example",
            "https://exa_mple.com",
        ):
            with self.subTest(value=value), self.assertRaises(analysis.InvalidTarget):
                analysis.parse_target(value)

    def test_private_mixed_and_reserved_dns_rejected(self):
        for addresses in (
            ("127.0.0.1",),
            ("169.254.169.254",),
            ("192.168.1.2",),
            ("::1",),
            ("::ffff:127.0.0.1",),
            ("93.184.216.34", "10.0.0.1"),
            ("224.0.0.1",),
        ):
            with self.subTest(addresses=addresses), patch(
                "analysis.socket.getaddrinfo", return_value=dns(*addresses)
            ), self.assertRaises(analysis.InvalidTarget):
                analysis.resolve_public("example.com")

    def test_pinned_connection_uses_checked_ip(self):
        connection = analysis.PinnedHTTPSConnection("example.com", "93.184.216.34")
        with patch("analysis.socket.create_connection") as connect:
            connection._create_connection(("example.com", 443), 4, None)
        connect.assert_called_once_with(("93.184.216.34", 443), 4, None)
        self.assertEqual(connection.host, "example.com")


class ProviderTests(unittest.TestCase):
    def setUp(self):
        self.target = analysis.parse_target("https://example.com/login?next=home")

    def test_missing_key_never_calls_provider(self):
        with patch("analysis.requests.post") as post:
            self.assertEqual(
                analysis.inspect_safe_browsing(self.target, "")["status"], "disabled"
            )
        post.assert_not_called()

    def test_http_error_is_unknown_not_clear(self):
        response = MagicMock(status_code=403)
        with patch("analysis.requests.post", return_value=response):
            result = analysis.inspect_safe_browsing(self.target, "test-key")
        self.assertEqual(result["status"], "unknown")

    def test_provider_response_validation(self):
        for payload in ({"error": {}}, [], {"matches": "bad"}, {"matches": [False]}):
            response = MagicMock(status_code=200)
            response.json.return_value = payload
            with self.subTest(payload=payload), patch(
                "analysis.requests.post", return_value=response
            ):
                self.assertEqual(
                    analysis.inspect_safe_browsing(self.target, "test-key")["status"],
                    "unknown",
                )

    def test_match_and_no_match_are_distinct(self):
        for payload, expected in (
            ({}, "clear"),
            ({"matches": [{"threatType": "MALWARE"}]}, "danger"),
        ):
            response = MagicMock(status_code=200)
            response.json.return_value = payload
            with self.subTest(payload=payload), patch(
                "analysis.requests.post", return_value=response
            ) as post:
                result = analysis.inspect_safe_browsing(self.target, "test-key")
                self.assertEqual(result["status"], expected)
                kwargs = post.call_args.kwargs
                self.assertEqual(
                    kwargs["json"]["threatInfo"]["threatEntries"][0]["url"],
                    self.target.url,
                )
                self.assertEqual(kwargs["timeout"], (4, 4))
                self.assertFalse(kwargs["allow_redirects"])

    def test_timeout_remains_unknown(self):
        with patch("analysis.requests.post", side_effect=analysis.requests.Timeout):
            self.assertEqual(
                analysis.inspect_safe_browsing(self.target, "test-key")["status"],
                "unknown",
            )

    def test_https_probe_reads_headers_without_following_redirect(self):
        connection = MagicMock()
        connection.getresponse.return_value.getheader.return_value = (
            "max-age=31536000; includeSubDomains"
        )
        with patch("analysis.PinnedHTTPSConnection", return_value=connection):
            result = analysis.inspect_https(self.target, "93.184.216.34")
        self.assertEqual([item["status"] for item in result], ["clear", "clear"])
        self.assertEqual(connection.request.call_args.args[:2], ("HEAD", "/"))
        connection.getresponse.return_value.read.assert_not_called()
        connection.close.assert_called_once()

    def test_certificate_failure_and_header_failure_are_distinct(self):
        connection = MagicMock()
        connection.connect.side_effect = ssl.SSLCertVerificationError("invalid")
        with patch("analysis.PinnedHTTPSConnection", return_value=connection):
            checks = analysis.inspect_https(self.target, "93.184.216.34")
        self.assertEqual([item["status"] for item in checks], ["warning", "unknown"])
        connection = MagicMock()
        connection.getresponse.side_effect = OSError("timeout")
        with patch("analysis.PinnedHTTPSConnection", return_value=connection):
            checks = analysis.inspect_https(self.target, "93.184.216.34")
        self.assertEqual([item["status"] for item in checks], ["clear", "unknown"])

    def test_hsts_max_age_zero_is_not_enabled(self):
        connection = MagicMock()
        connection.getresponse.return_value.getheader.return_value = "max-age=0"
        with patch("analysis.PinnedHTTPSConnection", return_value=connection):
            checks = analysis.inspect_https(self.target, "93.184.216.34")
        self.assertEqual(checks[1]["status"], "info")

    def test_incomplete_report_does_not_claim_low_risk(self):
        with patch("analysis.resolve_public", return_value="93.184.216.34"), patch(
            "analysis.inspect_https",
            return_value=[analysis.check("tls", "TLS", "unknown", "Timeout")],
        ):
            report = analysis.analyze_url(self.target.url)
        self.assertEqual(report["risk_score"], 0)
        self.assertEqual(report["risk_level"], "incomplete")
        self.assertTrue(report["incomplete"])

    def test_threat_match_keeps_high_risk_even_with_other_missing_data(self):
        with patch("analysis.resolve_public", return_value="93.184.216.34"), patch(
            "analysis.inspect_https",
            return_value=[analysis.check("tls", "TLS", "unknown", "Timeout")],
        ), patch(
            "analysis.inspect_safe_browsing",
            return_value=analysis.check("safe_browsing", "GSB", "danger", "Match", 80),
        ):
            report = analysis.analyze_url(self.target.url, "key")
        self.assertEqual(report["risk_level"], "high")
        self.assertEqual(report["risk_score"], 80)
        self.assertTrue(report["incomplete"])


class APITests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_home_and_static_assets(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Content-Security-Policy", response.headers)
        for asset in ("styles.css", "app.js", "logo.png"):
            with self.client.get("/static/" + asset) as asset_response:
                self.assertEqual(asset_response.status_code, 200)

    def test_missing_or_malformed_input_is_400(self):
        for payload in ({}, {"url": None}, [], {"url": "bad"}):
            with self.subTest(payload=payload):
                self.assertEqual(
                    self.client.post("/api/analyze", json=payload).status_code, 400
                )
        self.assertEqual(self.client.get("/check_domain").status_code, 400)

    def test_private_target_never_reaches_probes(self):
        with patch("analysis.socket.getaddrinfo", return_value=dns("10.0.0.1")), patch(
            "analysis.inspect_https"
        ) as probe:
            response = self.client.post(
                "/api/analyze", json={"url": "https://example.com"}
            )
        self.assertEqual(response.status_code, 400)
        probe.assert_not_called()

    def test_json_and_size_requirements(self):
        self.assertEqual(
            self.client.post("/api/analyze", data="url=example.com").status_code, 415
        )
        self.assertEqual(
            self.client.post("/api/analyze", json={"url": "a" * 5000}).status_code, 413
        )

    def test_busy_returns_429_and_does_not_start_analysis(self):
        for _ in range(4):
            analysis_slots.acquire()
        try:
            with patch("app.analyze_url") as analyze:
                self.assertEqual(
                    self.client.post(
                        "/api/analyze", json={"url": "example.com"}
                    ).status_code,
                    429,
                )
                analyze.assert_not_called()
        finally:
            for _ in range(4):
                analysis_slots.release()


if __name__ == "__main__":
    unittest.main()
