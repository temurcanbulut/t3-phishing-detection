import asyncio
import hashlib
import sys
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from urllib.parse import urlsplit

import aiohttp
import dns.resolver
from aiohttp import web
from hypothesis import given, settings
from hypothesis import strategies as st
from yarl import URL

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "T3-Phishing-Detection"))
from app import analysis_slots, app
from t3core.content import extract_page
from t3core.inspector import evidence, inspect_url, probe_dns_policy, validate_threat_response
from t3core.target import InvalidTarget, is_public, parse_target
from t3core.transport import PublicResolver, session_for


class TargetTests(unittest.TestCase):
    def test_preserves_path_and_query_not_fragment(self):
        target = parse_target("HTTPS://Example.COM:443/a/b?x=1&y=2#fragment")
        self.assertEqual(target.url, "https://example.com/a/b?x=1&y=2")

    def test_unicode_idna_and_public_suffix_private_domains(self):
        self.assertEqual(parse_target("bücher.de").host, "xn--bcher-kva.de")
        self.assertEqual(parse_target("login.example.co.uk").registrable_domain, "example.co.uk")
        self.assertEqual(parse_target("foo.github.io").registrable_domain, "foo.github.io")
        self.assertEqual(
            parse_target("example.com/şifre?x=ü").url, "https://example.com/%C5%9Fifre?x=%C3%BC"
        )

    def test_private_and_ambiguous_targets(self):
        cases = [
            None,
            "",
            [],
            "ftp://example.com",
            "https://good.example@evil.example",
            "https://a:b@example.com",
            "http://example.com:81",
            "https://example.com\\@localhost",
            "127.0.0.1",
            "169.254.169.254",
            "[::1]",
            "[::ffff:127.0.0.1]",
            "[2002:7f00:1::]",
            "0177.0.0.1",
            "127.1",
            "2130706433",
            "https://example.com/%zz",
            "https://exa_mple.com",
            "https://[fe80::1%25eth0]",
            "example.com\nX-Header:1",
            "example.com/\u00a0path",
        ]
        for value in cases:
            with self.subTest(value=value), self.assertRaises(InvalidTarget):
                parse_target(value)

    def test_public_address_policy(self):
        for ip in (
            "10.0.0.1",
            "192.168.1.1",
            "224.0.0.1",
            "0.0.0.0",
            "::",
            "ff02::1",
            "100.64.0.1",
            "::ffff:127.0.0.1",
            "2001:db8::1",
            "not-an-ip",
        ):
            self.assertFalse(is_public(ip), ip)
        self.assertTrue(is_public("8.8.8.8"))

    @settings(max_examples=1000, deadline=None, derandomize=True)
    @given(
        st.sampled_from(
            ["example.com", "bücher.de", "login.example.co.uk", "[2606:4700:4700::1111]"]
        ),
        st.text(alphabet=st.characters(whitelist_categories=("L", "N")), max_size=100),
    )
    def test_valid_unicode_paths_roundtrip_without_changing_authority(self, host, path):
        target = parse_target(f"https://{host}/{path}?q={path}")
        self.assertEqual(parse_target(target.url), target)
        self.assertEqual(urlsplit(target.url).hostname, target.host)

    @settings(max_examples=1500, deadline=None, derandomize=True)
    @given(st.text(max_size=300))
    def test_arbitrary_input_is_rejected_or_canonical_and_credential_free(self, value):
        try:
            target = parse_target(value)
        except InvalidTarget:
            return
        self.assertEqual(parse_target(target.url), target)
        parsed = urlsplit(target.url)
        self.assertIsNone(parsed.username)
        self.assertIsNone(parsed.password)
        self.assertNotIn("\\", target.url)
        self.assertEqual(parsed.hostname, target.host)


class ContentTests(unittest.TestCase):
    def test_credential_form_uses_base_url_and_reports_objective_action(self):
        facts, findings = extract_page(
            '<base href="https://other.example/"><form action="http://other.example/post"><input type="password"></form>',
            "https://example.com/login",
        )
        self.assertEqual(facts["forms"][0]["password_fields"], 1)
        self.assertEqual(
            {item["kind"] for item in findings},
            {"credential_form_cross_host", "credential_form_non_https"},
        )

    def test_scripts_are_only_counted_and_form_count_bounded(self):
        facts, _ = extract_page(
            '<title>&lt;script&gt;</title><script src="https://bad.example/x"></script>'
            + '<form action="/"><input type="password"></form>' * 100,
            "https://example.com/",
        )
        self.assertEqual(facts["title"], "<script>")
        self.assertEqual(facts["script_elements"], 1)
        self.assertEqual(len(facts["forms"]), 50)


class ThreatTests(unittest.TestCase):
    def test_empty_response_means_no_match_not_safe(self):
        self.assertEqual(validate_threat_response({}, parse_target("example.com")), [])

    def test_malformed_or_wrong_url_cannot_produce_match(self):
        cases = [
            [],
            {"error": {}},
            {"matches": "bad"},
            {"matches": [{}]},
            {"matches": [{"threatType": "MALWARE", "threat": {"url": "https://other.example/"}}]},
        ]
        for payload in cases:
            with self.subTest(payload=payload), self.assertRaises((ValueError, InvalidTarget)):
                validate_threat_response(payload, parse_target("example.com"))

    def test_valid_threat_match_has_source_details(self):
        match = {
            "threatType": "SOCIAL_ENGINEERING",
            "threat": {"url": "https://example.com/"},
            "cacheDuration": "300s",
        }
        result = validate_threat_response({"matches": [match]}, parse_target("example.com"))
        self.assertEqual(result[0]["threat_type"], "SOCIAL_ENGINEERING")


class DNSTests(unittest.IsolatedAsyncioTestCase):
    async def test_absent_mail_policy_is_observation_not_phishing_finding(self):
        resolver = PublicResolver()
        resolver.resolver.resolve = AsyncMock(side_effect=dns.resolver.NoAnswer())
        result = await probe_dns_policy(parse_target("example.com"), resolver)
        self.assertEqual(result["status"], "observed")
        self.assertTrue(all(item["status"] == "no_record" for item in result["data"]))

    async def test_mixed_private_public_answers_fail_closed(self):
        resolver = PublicResolver()

        async def answer(_host, kind, **_options):
            return [SimpleNamespace(address="8.8.8.8" if kind == "A" else "::1")]

        resolver.resolver.resolve = AsyncMock(side_effect=answer)
        with self.assertRaises(InvalidTarget):
            await resolver.addresses("example.com")

    async def test_checked_results_are_pinned_not_resolved_again(self):
        resolver = PublicResolver()

        async def answer(_host, kind, **_options):
            if kind == "AAAA":
                raise dns.resolver.NoAnswer()
            return [SimpleNamespace(address="8.8.8.8")]

        resolver.resolver.resolve = AsyncMock(side_effect=answer)
        self.assertEqual(await resolver.addresses("example.com"), ["8.8.8.8"])
        self.assertEqual((await resolver.resolve("example.com", 443))[0]["host"], "8.8.8.8")
        self.assertEqual(resolver.resolver.resolve.await_count, 2)

    async def test_passive_mode_performs_no_network(self):
        with (
            patch("t3core.inspector.session_for") as session,
            patch.object(PublicResolver, "addresses", new_callable=AsyncMock) as resolver,
        ):
            report = await inspect_url("example.com")
        session.assert_not_called()
        resolver.assert_not_awaited()
        self.assertEqual(report["conclusion"], "no_safety_verdict")
        self.assertNotIn("risk_score", report)


class HTTPIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.hits = []
        self.raw_hits = []

        async def handler(request):
            self.hits.append(request.path)
            self.raw_hits.append(request.raw_path)
            if request.path == "/many-headers":
                return web.Response(
                    text="bounded", headers={f"X-Field-{i}": "x" for i in range(100)}
                )
            if request.path == "/private":
                return web.Response(status=302, headers={"Location": "http://127.0.0.1/admin"})
            if request.path == "/loop":
                return web.Response(status=302, headers={"Location": "/loop"})
            if request.path == "/downgrade":
                return web.Response(status=302, headers={"Location": "http://public.example/final"})
            if request.path == "/huge":
                return web.Response(body=b"x" * 200000, content_type="text/html")
            if request.path == "/encoded":
                return web.Response(
                    body=b"not decompressed",
                    headers={"Content-Encoding": "gzip", "Content-Type": "text/html"},
                )
            if request.path == "/slow":
                response = web.StreamResponse(headers={"Content-Type": "text/html"})
                await response.prepare(request)
                try:
                    for _ in range(10):
                        await response.write(b"x")
                        await asyncio.sleep(0.05)
                except (ConnectionResetError, aiohttp.ClientConnectionError):
                    pass
                return response
            return web.Response(
                text='<title>Fixture</title><form action="http://other.example/collect"><input type="password"></form>',
                content_type="text/html",
            )

        app = web.Application()
        app.router.add_route("*", "/{path:.*}", handler)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        self.server = web.TCPSite(self.runner, "127.0.0.1", 0)
        await self.server.start()
        self.port = self.server._server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        await self.runner.cleanup()

    async def collect(self, path, timeout=2, scheme="http"):
        # Test-only routing adapter maps a public-shaped URL to our local fixture.
        # Production still uses PublicResolver and a verified TLS connector.
        class LocalSession:
            async def __aenter__(inside):
                inside.session = aiohttp.ClientSession(auto_decompress=False)
                return inside

            async def __aexit__(inside, *args):
                await inside.session.close()

            def get(inside, url, **kwargs):
                parsed = urlsplit(str(url))
                return inside.session.get(
                    URL(f"http://127.0.0.1:{self.port}{parsed.path}?{parsed.query}", encoded=True),
                    **kwargs,
                )

        with (
            patch.object(
                PublicResolver, "addresses", new_callable=AsyncMock, return_value=["8.8.8.8"]
            ),
            patch("t3core.inspector.session_for", return_value=LocalSession()),
            patch(
                "t3core.inspector.probe_dns_policy",
                new_callable=AsyncMock,
                return_value=evidence("dns_policy", "DNS policy", "not_run"),
            ),
            patch(
                "t3core.inspector.probe_tls",
                new_callable=AsyncMock,
                return_value=evidence("tls", "TLS", "not_run"),
            ),
        ):
            return await inspect_url(
                f"{scheme}://public.example{path}", active=True, timeout=timeout
            )

    async def test_private_redirect_is_blocked_before_second_request(self):
        report = await self.collect("/private")
        self.assertEqual(self.hits, ["/private"])
        self.assertEqual(
            next(item for item in report["evidence"] if item["id"] == "http")["status"], "blocked"
        )

    async def test_actual_transport_bounds_response_header_count(self):
        # Map only this owned fixture; production PublicResolver still rejects loopback.
        resolver = PublicResolver()
        resolver.addresses = AsyncMock(return_value=["127.0.0.1"])
        async with session_for(resolver) as session:
            with self.assertRaises(aiohttp.ClientError):
                async with session.get(f"http://public.example:{self.port}/many-headers"):
                    self.fail("Excess response headers were accepted")

    async def test_redirect_loop_stops_and_records_chain(self):
        report = await self.collect("/loop")
        self.assertEqual(self.hits, ["/loop"])
        self.assertTrue(report["partial"])

    async def test_https_downgrade_is_an_observed_finding(self):
        report = await self.collect("/downgrade", scheme="https")
        self.assertIn("https_downgrade", {item["kind"] for item in report["findings"]})

    async def test_response_size_limit_and_fingerprint(self):
        report = await self.collect("/huge")
        item = next(item for item in report["evidence"] if item["id"] == "http")
        hop = item["data"][0]
        self.assertEqual(hop["body_bytes_collected"], 131072)
        self.assertTrue(hop["body_truncated"])
        self.assertEqual(hop["body_sha256"], hashlib.sha256(b"x" * 131072).hexdigest())

    async def test_compressed_body_is_not_decompressed_or_parsed(self):
        report = await self.collect("/encoded")
        item = next(item for item in report["evidence"] if item["id"] == "http")
        self.assertEqual(item["data"][0]["content_analysis"], "not_run_encoded_body")
        self.assertTrue(report["partial"])

    async def test_escaped_path_query_and_dot_segments_are_preserved_on_wire(self):
        path = "/a/../raw%2fitem?q=%2f%20&token=a%2Bb"
        report = await self.collect(path)
        self.assertEqual(self.raw_hits, [path])
        hop = next(x for x in report["evidence"] if x["id"] == "http")["data"][0]
        self.assertTrue(hop["serialized_request_url"].endswith(path))

    async def test_slow_stream_hits_overall_deadline(self):
        started = time.perf_counter()
        report = await self.collect("/slow", timeout=0.12)
        self.assertLess(time.perf_counter() - started, 0.7)
        self.assertTrue(report["partial"])
        self.assertIn("deadline", {item["id"] for item in report["evidence"]})

    async def test_content_findings_are_evidence_not_phishing_verdict(self):
        report = await self.collect("/final")
        self.assertEqual(report["conclusion"], "no_safety_verdict")
        self.assertTrue(report["findings"])


class APITests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_missing_or_malformed_input(self):
        for value in (
            {},
            [],
            {"url": None},
            {"url": "bad"},
            {"url": "example.com", "active": "true"},
        ):
            with self.subTest(value=value):
                self.assertEqual(self.client.post("/api/analyze", json=value).status_code, 400)

    def test_foreign_origin_and_rebinding_host_blocked(self):
        self.assertEqual(
            self.client.post(
                "/api/analyze",
                json={"url": "example.com"},
                headers={"Origin": "https://evil.example"},
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.post(
                "/api/analyze", json={"url": "example.com"}, headers={"Host": "evil.example"}
            ).status_code,
            400,
        )

    def test_legacy_get_does_not_trigger_network(self):
        with patch("app.analyze_url") as analyze:
            self.assertEqual(self.client.get("/check_domain?domain=example.com").status_code, 405)
            analyze.assert_not_called()

    def test_passive_post_has_no_score_or_safety_verdict(self):
        response = self.client.post("/api/analyze", json={"url": "example.com"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["conclusion"], "no_safety_verdict")
        self.assertNotIn("risk_score", response.json)

    def test_input_limits(self):
        self.assertEqual(self.client.post("/api/analyze", data="url=example.com").status_code, 415)
        self.assertEqual(
            self.client.post("/api/analyze", json={"url": "a" * 5000}).status_code, 413
        )

    def test_concurrency_limit(self):
        for _ in range(4):
            analysis_slots.acquire()
        try:
            self.assertEqual(
                self.client.post("/api/analyze", json={"url": "example.com"}).status_code, 429
            )
        finally:
            for _ in range(4):
                analysis_slots.release()


if __name__ == "__main__":
    unittest.main()
