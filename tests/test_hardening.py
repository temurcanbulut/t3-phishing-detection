import asyncio
import json
import sys
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from hypothesis import given, settings
from hypothesis import strategies as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "T3-Phishing-Detection"))
from t3core.content import extract_page
from t3core.inspector import evidence, inspect_url, probe_dns_policy, probe_threats
from t3core.target import InvalidTarget, is_public, parse_target
from t3core.transport import PublicResolver


class FormSemanticsTests(unittest.TestCase):
    def test_long_base_url_cannot_amplify_report_through_many_submit_buttons(self):
        html = (
            '<base href="http://other.example/'
            + "😀" * 1000
            + '/"><form><input type="password">'
            + "".join(f'<button formaction="{i}">Go</button>' for i in range(100))
            + "</form>"
        )
        facts, findings = extract_page(html, "https://example.com/")
        self.assertTrue(facts["limited"])
        self.assertLess(len(json.dumps([facts, findings], ensure_ascii=True)), 130000)

    def test_invalid_button_type_defaults_to_submit(self):
        _, findings = extract_page(
            '<form><input type="password"><button type="invalid" formaction="http://other.example">Go</button></form>',
            "https://example.com/",
        )
        self.assertIn("credential_form_cross_host", {x["kind"] for x in findings})

    def test_single_large_tag_and_many_duplicate_attributes_are_bounded_early(self):
        started = time.perf_counter()
        for html in (
            "<form " + " ".join(f"a{i}=x" for i in range(14000)) + "></form>",
            "<form " + "a=x " * 30000,
        ):
            facts, _ = extract_page(html, "https://example.com/")
            self.assertTrue(facts["limited"])
        self.assertLess(time.perf_counter() - started, 1)

    def test_unicode_and_ascii_host_aliases_do_not_produce_cross_host_finding(self):
        _, findings = extract_page(
            '<form action="https://BÜCHER.DE/post"><input type="password"></form>',
            "https://xn--bcher-kva.de/",
        )
        self.assertEqual(findings, [])

    def test_ambiguous_backslash_action_is_not_presented_as_resolved_host(self):
        _, findings = extract_page(
            '<form action="https://good.example\\@evil.example"><input type="password"></form>',
            "https://example.com/",
        )
        self.assertEqual({x["kind"] for x in findings}, {"credential_form_invalid_action"})

    def test_javascript_action_has_no_invented_cross_host_destination(self):
        _, findings = extract_page(
            '<form action="javascript:submitForm()"><input type="password"></form>',
            "https://example.com/",
        )
        self.assertNotIn("credential_form_cross_host", {x["kind"] for x in findings})

    def test_external_controls_and_submit_override_are_associated(self):
        facts, findings = extract_page(
            '<form id="login" action="/ok"></form><input form="login" type="password"><button form="login" formaction="http://other.example/post">Go</button>',
            "https://example.com/",
        )
        self.assertEqual(facts["forms"][0]["password_fields"], 1)
        self.assertEqual(
            {x["kind"] for x in findings},
            {"credential_form_non_https", "credential_form_cross_host"},
        )

    def test_base_after_form_applies_to_earlier_relative_actions(self):
        facts, _ = extract_page(
            '<form action="post"><input type="password"></form><base href="https://other.example/path/">',
            "https://example.com/",
        )
        self.assertEqual(facts["forms"][0]["action"], "https://other.example/path/post")

    def test_empty_action_uses_document_not_base(self):
        facts, findings = extract_page(
            '<base href="http://other.example"><form action=""><input type="password"></form>',
            "https://example.com/login",
        )
        self.assertEqual(facts["forms"][0]["action"], "https://example.com/login")
        self.assertEqual(findings, [])

    def test_explicit_invalid_form_owner_does_not_fall_back_to_ancestor(self):
        facts, findings = extract_page(
            '<form action="http://other.example"><input form="missing" type="password"></form>',
            "https://example.com/",
        )
        self.assertEqual(facts["forms"][0]["password_fields"], 0)
        self.assertEqual(findings, [])

    def test_duplicate_id_on_nonform_prevents_association(self):
        facts, _ = extract_page(
            '<div id="login"></div><form id="login"></form><input form="login" type="password">',
            "https://example.com/",
        )
        self.assertEqual(facts["forms"][0]["password_fields"], 0)

    def test_template_and_disabled_controls_are_not_active_submissions(self):
        html = '<template><form action="http://evil.example"><input type="password"></form></template><form action="http://other.example"><fieldset disabled><input type="password"></fieldset></form>'
        facts, findings = extract_page(html, "https://example.com/")
        self.assertEqual(len(facts["forms"]), 1)
        self.assertEqual(facts["forms"][0]["disabled_password_fields"], 1)
        self.assertEqual(findings, [])

    def test_first_legend_of_disabled_fieldset_remains_enabled(self):
        facts, findings = extract_page(
            '<form action="http://other.example"><fieldset disabled><legend><input type="password"></legend><input type="password"></fieldset></form>',
            "https://example.com/",
        )
        self.assertEqual(facts["forms"][0]["password_fields"], 2)
        self.assertEqual(facts["forms"][0]["disabled_password_fields"], 1)
        self.assertTrue(findings)

    def test_form_limit_does_not_assign_extra_fields_to_previous_form(self):
        html = (
            "<form></form>" * 50
            + '<form action="http://other.example"><input type="password"></form>'
        )
        facts, findings = extract_page(html, "https://example.com/")
        self.assertTrue(facts["limited"])
        self.assertTrue(all(f["password_fields"] == 0 for f in facts["forms"]))
        self.assertEqual(findings, [])

    def test_malformed_action_does_not_discard_other_page_evidence(self):
        facts, findings = extract_page(
            '<title>Still collected</title><form action="https://[broken"><input type="password"></form>',
            "https://example.com/",
        )
        self.assertEqual(facts["title"], "Still collected")
        self.assertEqual(findings[0]["kind"], "credential_form_invalid_action")

    def test_html_declared_encoding_is_used(self):
        facts, _ = extract_page(
            '<meta charset="windows-1254"><title>şifre</title>'.encode("cp1254"),
            "https://example.com/",
        )
        self.assertEqual(facts["title"], "şifre")

    def test_deep_and_large_html_stop_with_explicit_limit(self):
        started = time.perf_counter()
        for html in ("<b>" * 20000, "<div></div>" * 12000):
            facts, _ = extract_page(html, "https://example.com/")
            self.assertTrue(facts["limited"])
        self.assertLess(time.perf_counter() - started, 2)

    @settings(max_examples=500, deadline=None, derandomize=True)
    @given(st.text(max_size=400))
    def test_arbitrary_text_remains_serializable_source_data(self, text):
        facts, findings = extract_page(text, "https://example.com/")
        json.dumps([facts, findings])


class OrchestrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_concurrent_dns_probes_share_exactly_one_pin(self):
        resolver = PublicResolver()

        async def answer(_host, kind, **_options):
            await asyncio.sleep(0.01)
            return [SimpleNamespace(address="8.8.8.8")] if kind == "A" else []

        resolver.resolver.resolve = AsyncMock(side_effect=answer)
        results = await asyncio.gather(*(resolver.addresses("example.com") for _ in range(20)))
        self.assertTrue(all(x == ["8.8.8.8"] for x in results))
        self.assertEqual(resolver.resolver.resolve.await_count, 2)

    async def test_split_txt_strings_preserve_spf_version(self):
        resolver = PublicResolver()

        async def answer(name, kind, **options):
            if kind == "TXT":
                return [
                    SimpleNamespace(
                        strings=(b"v=sp", b"f1 -all"), to_text=lambda: '"v=sp" "f1 -all"'
                    )
                ]
            return []

        resolver.resolver.resolve = AsyncMock(side_effect=answer)
        result = await probe_dns_policy(parse_target("example.com"), resolver)
        self.assertIn("v=spf1 -all", result["data"][2]["records"])

    async def test_deadline_leaves_a_status_for_every_requested_check(self):
        class Session:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

        async def hang(*args, **kwargs):
            await asyncio.sleep(10)

        with (
            patch("t3core.inspector.session_for", return_value=Session()),
            patch.object(PublicResolver, "addresses", side_effect=hang),
            patch("t3core.inspector.probe_dns_policy", side_effect=hang),
            patch("t3core.inspector.probe_tls", side_effect=hang),
            patch("t3core.inspector.probe_http", side_effect=hang),
            patch("t3core.inspector.probe_threats", side_effect=hang),
        ):
            report = await inspect_url("example.com", active=True, threat_lookup=True, timeout=0.05)
        statuses = {x["id"]: x["status"] for x in report["evidence"]}
        for identifier in ("dns", "http", "tls", "dns_policy", "threat_lists"):
            self.assertEqual(statuses[identifier], "unavailable")
        self.assertTrue(report["partial"])

    async def test_target_dns_failure_does_not_skip_independent_threat_provider(self):
        class Session:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

        with (
            patch("t3core.inspector.session_for", return_value=Session()),
            patch.object(
                PublicResolver, "addresses", new_callable=AsyncMock, side_effect=OSError("fixture")
            ),
            patch(
                "t3core.inspector.probe_dns_policy",
                new_callable=AsyncMock,
                return_value=evidence("dns_policy", "DNS", "unavailable"),
            ),
            patch(
                "t3core.inspector.probe_threats",
                new_callable=AsyncMock,
                return_value=evidence("threat_lists", "Provider", "no_match"),
            ) as threat,
        ):
            report = await inspect_url("example.com", active=True, threat_lookup=True)
        threat.assert_awaited_once()
        self.assertTrue(report["partial"])
        self.assertEqual(report["conclusion"], "no_safety_verdict")

    async def test_provider_http_schema_and_exact_payload(self):
        from urllib.parse import urlsplit

        import aiohttp
        from aiohttp import web

        received = []

        async def handler(request):
            received.append(await request.json())
            return web.json_response(
                {
                    "matches": [
                        {
                            "threatType": "SOCIAL_ENGINEERING",
                            "threat": {"url": "https://example.com/login?x=1"},
                        }
                    ]
                }
            )

        fixture = web.Application()
        fixture.router.add_post("/v4/threatMatches:find", handler)
        runner = web.AppRunner(fixture)
        await runner.setup()
        server = web.TCPSite(runner, "127.0.0.1", 0)
        await server.start()
        port = server._server.sockets[0].getsockname()[1]
        try:
            async with aiohttp.ClientSession() as actual:

                class Adapter:
                    def post(self, url, **options):
                        self_url = f"http://127.0.0.1:{port}{urlsplit(url).path}"
                        return actual.post(self_url, **options)

                result = await probe_threats(
                    parse_target("https://example.com/login?x=1"), "fixture-key", Adapter()
                )
            self.assertEqual(result["status"], "matched")
            self.assertEqual(
                received[0]["threatInfo"]["threatEntries"],
                [{"url": "https://example.com/login?x=1"}],
            )
        finally:
            await runner.cleanup()


class TranslationAddressTests(unittest.TestCase):
    def test_translation_ranges_and_multiple_trailing_dots_are_rejected(self):
        for value in ("64:ff9b::7f00:1", "64:ff9b:1::a00:1"):
            self.assertFalse(is_public(value))
        with self.assertRaises(InvalidTarget):
            parse_target("https://example.com../")
