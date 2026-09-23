from datetime import datetime, timezone
import unittest

from subssl.config import Config
from subssl.prometheus import certificate_type, render_metrics
from subssl.scanner import ScanHost, TLSView


class PrometheusMetricsTests(unittest.TestCase):
    def test_certificate_type_describes_issuer_and_wildcard(self):
        self.assertEqual(certificate_type("api.example.com", "CN=R10,O=Let's Encrypt,C=US", []), "Let's Encrypt")
        self.assertEqual(certificate_type("*.example.com", "CN=R11,O=Let's Encrypt,C=US", ["*.example.com"]), "Wildcard · Let's Encrypt")

    def test_metrics_have_hostname_label_and_success_data(self):
        cfg = Config(domain="example.com")
        host = ScanHost(
            hostname="api.example.com",
            record_types=["A"],
            tls=[TLSView(
                ip="192.0.2.1", port=443, ok=True, subject_cn="api.example.com",
                issuer="CN=Example CA", serial_hex="01", sha256="abc", not_before="2029-01-01T00:00:00+00:00", not_after="2030-01-01T00:00:00+00:00",
                days_left=10, expired=False, host_matches_cert=True,
            )],
        )
        payload = render_metrics(cfg, [host], datetime(2026, 1, 1, tzinfo=timezone.utc))
        self.assertIn('hostname="api.example.com"', payload)
        self.assertIn("subssl_tls_probe_success", payload)
        self.assertIn("subssl_tls_certificate_expiry_timestamp_seconds", payload)
        self.assertIn('subssl_tls_certificate_present{domain="example.com",hostname="api.example.com",endpoint="192.0.2.1:443",not_before="01.01.2029",not_after="01.01.2030",certificate_type="Example CA",tls_error=""} 1', payload)

    def test_failed_probe_only_exports_probe_status(self):
        cfg = Config(domain="example.com")
        host = ScanHost(hostname="bad.example.com", record_types=["A"], tls=[TLSView(ip="192.0.2.2", port=443, ok=False, error="TimeoutError: timed out")])
        payload = render_metrics(cfg, [host], datetime(2026, 1, 1, tzinfo=timezone.utc))
        self.assertIn("subssl_tls_probe_success{domain=\"example.com\",hostname=\"bad.example.com\",ip=\"192.0.2.2\",port=\"443\",tls_error=\"TimeoutError: timed out\"} 0", payload)
        self.assertNotIn("subssl_tls_certificate_info{domain=\"example.com\",hostname=\"bad.example.com\"", payload)
        self.assertIn('subssl_tls_certificate_present{domain="example.com",hostname="bad.example.com",endpoint="192.0.2.2:443",not_before="",not_after="",certificate_type="",tls_error="TimeoutError: timed out"} 0', payload)
