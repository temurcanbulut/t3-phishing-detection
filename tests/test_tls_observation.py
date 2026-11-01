"""The evidence-only retry never changes HTTP TLS trust or DNS pinning."""

import asyncio
import ssl
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "T3-Phishing-Detection"))
from t3core.inspector import probe_tls
from t3core.target import parse_target


class TLSObservationTests(unittest.TestCase):
    def test_failed_verification_observes_only_same_pinned_ip(self):
        resolver = SimpleNamespace(addresses=AsyncMock(return_value=["93.184.216.34"]))
        failure = ssl.SSLCertVerificationError(1, "fixture")
        failure.verify_code = 18
        secure = MagicMock()
        secure.getpeercert.return_value = b"fixture-der"
        writer = MagicMock()
        writer.get_extra_info.return_value = secure
        writer.wait_closed = AsyncMock()
        certificate = MagicMock()
        certificate.not_valid_before_utc.isoformat.return_value = "2026-01-01"
        certificate.not_valid_after_utc.isoformat.return_value = "2027-01-01"
        with patch("t3core.inspector.asyncio.open_connection", new_callable=AsyncMock) as connect:
            connect.side_effect = [failure, (None, writer)]
            with patch("t3core.inspector.x509.load_der_x509_certificate", return_value=certificate):
                result = asyncio.run(probe_tls(parse_target("https://example.com"), resolver))
        self.assertEqual(result["status"], "verification_failed")
        self.assertEqual(result["data"]["observation"], "unverified_certificate_only")
        self.assertEqual(resolver.addresses.await_count, 1)
        for call in connect.call_args_list:
            self.assertEqual(call.args, ("93.184.216.34", 443))
            self.assertEqual(call.kwargs["server_hostname"], "example.com")
        self.assertEqual(connect.call_args_list[0].kwargs["ssl"].verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual(connect.call_args_list[1].kwargs["ssl"].verify_mode, ssl.CERT_NONE)
        writer.write.assert_not_called()
        writer.close.assert_called_once()

    def test_unavailable_retry_keeps_verification_failure(self):
        resolver = SimpleNamespace(addresses=AsyncMock(return_value=["93.184.216.34"]))
        failure = ssl.SSLCertVerificationError(1, "fixture")
        failure.verify_code = 18
        with patch("t3core.inspector.asyncio.open_connection", new_callable=AsyncMock) as connect:
            connect.side_effect = [failure, TimeoutError()]
            result = asyncio.run(probe_tls(parse_target("example.com"), resolver))
        self.assertEqual(result["status"], "verification_failed")
        self.assertEqual(result["data"]["observation"], "unavailable")
