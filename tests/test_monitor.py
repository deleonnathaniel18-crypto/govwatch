#!/usr/bin/env python3
"""Unit tests for GovSource Watch monitoring engine."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import monitor  # noqa: E402


class TestMonitor(unittest.TestCase):
    def test_valid_govph_url(self):
        self.assertTrue(monitor.is_valid_govph_url("https://openstat.psa.gov.ph/PXWeb/api/v1/en"))
        self.assertFalse(monitor.is_valid_govph_url("http://psa.gov.ph"))
        self.assertFalse(monitor.is_valid_govph_url("https://example.com"))

    def test_waf_detection(self):
        self.assertTrue(
            monitor.detect_waf_block(
                403, {"Server": "cloudflare", "CF-RAY": "abc"}, "<html>Just a moment...</html>"
            )
        )
        self.assertTrue(monitor.detect_waf_block(403, {"cf-mitigated": "challenge"}, ""))
        self.assertFalse(monitor.detect_waf_block(503, {"Server": "nginx"}, "Service Unavailable"))
        self.assertFalse(
            monitor.detect_waf_block(503, {"Server": "cloudflare", "CF-RAY": "abc"}, "Service Unavailable")
        )

    def test_empty_exception_message_formatting(self):
        exc = TimeoutError()
        msg = str(exc).strip()
        formatted = f"{type(exc).__name__}: {msg}" if msg else type(exc).__name__
        self.assertEqual(formatted, "TimeoutError")

    def test_relay_payload_classification(self):
        ok_res = monitor.classify_relay_payload({"http_status": 200, "response_time_ms": 95}, [200])
        self.assertEqual(ok_res["outcome"], "online")
        waf_res = monitor.classify_relay_payload(
            {"http_status": 403, "headers": {"server": "cloudflare"}, "snippet": "Just a moment"},
            [200],
        )
        self.assertEqual(waf_res["outcome"], "monitoring_restricted")
        down_res = monitor.classify_relay_payload(
            {"http_status": 503, "headers": {"server": "cloudflare", "cf-ray": "xyz"}, "snippet": "Down"},
            [200],
        )
        self.assertEqual(down_res["outcome"], "issues")
        ssl_res = monitor.classify_relay_payload({"http_status": 526, "response_time_ms": 110}, [200])
        self.assertEqual(ssl_res["outcome"], "monitoring_restricted")

    def test_incident_state_machine(self):
        data = {"incidents": []}
        monitor.update_incidents(data, "psa-main", "experiencing_issues", 1, 503, "2026-11-26T00:00:00Z")
        self.assertEqual(len(data["incidents"]), 0)

        monitor.update_incidents(data, "psa-main", "unavailable", 2, 503, "2026-11-26T04:00:00Z")
        self.assertEqual(len(data["incidents"]), 1)
        self.assertEqual(data["incidents"][0]["status"], "open")

        monitor.update_incidents(data, "psa-main", "online", 0, 200, "2026-11-26T08:00:00Z")
        self.assertEqual(data["incidents"][0]["status"], "resolved")
        self.assertEqual(data["incidents"][0]["resolved_at"], "2026-11-26T08:00:00Z")

    def test_daily_history_and_uptime(self):
        with tempfile.TemporaryDirectory() as tmp:
            hdir = Path(tmp)
            today = monitor.utc_today()
            monitor.update_daily_history(hdir, "src-1", today, "online", 120)
            monitor.update_daily_history(hdir, "src-1", today, "monitoring_restricted", 80)
            monitor.update_daily_history(hdir, "src-1", today, "unavailable", None)

            pct, count = monitor.compute_30d_uptime(hdir, "src-1")
            # Restricted check is excluded from valid denominator: 1 online / 2 valid = 50.0%
            self.assertEqual(count, 2)
            self.assertEqual(pct, 50.0)


if __name__ == "__main__":
    unittest.main()
