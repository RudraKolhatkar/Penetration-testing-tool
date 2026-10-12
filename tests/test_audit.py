"""Automated tests for penetration testing modules using an in-process mock server."""

import threading
import time
import unittest
from http.server import HTTPServer

from pentest_tool.modules.port_scanner import PortScanner
from pentest_tool.modules.web_auditor import WebAuditor
from pentest_tool.modules.stress_auditor import StressAuditor
from pentest_tool.reporter import Reporter, SEVERITY_ORDER
from scripts.mock_target import MockVulnerableHandler


class TestPentestTool(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = 8899
        cls.server = HTTPServer(("127.0.0.1", cls.port), MockVulnerableHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        import os
        for f in ("test_output.json", "test_output.md"):
            if os.path.exists(f):
                os.remove(f)

    def test_port_scanner_detects_open_port(self):
        scanner = PortScanner("127.0.0.1", ports=[self.port])
        scanner.run()
        ports = [int(p["port"]) for p in scanner.open_ports]
        self.assertIn(self.port, ports)

    def test_web_auditor_flags_missing_headers_and_leaks(self):
        target_url = f"http://127.0.0.1:{self.port}"
        auditor = WebAuditor(target_url)
        findings = auditor.run()
        titles = [f.title for f in findings]

        # Missing hardening headers checks
        self.assertTrue(any("Optional Security Header Omitted: Content-Security-Policy" in t for t in titles))
        self.assertTrue(any("Optional Security Header Omitted: X-Frame-Options" in t for t in titles))

        # Information disclosure / fingerprinting
        self.assertTrue(any("Server Fingerprint in Header: Server" in t for t in titles))

        # Sensitive paths checks & public discovery
        self.assertTrue(any("Exposed Resource: /.env" in t for t in titles))
        self.assertTrue(any("Exposed Resource: /.aws/credentials" in t for t in titles))
        self.assertTrue(any("Exposed Resource: /id_rsa" in t for t in titles))
        self.assertTrue(any("Exposed Resource: /actuator/env" in t for t in titles))
        self.assertTrue(any("Exposed Resource: /.git/HEAD" in t for t in titles))
        self.assertTrue(any("Public Discovery: /robots.txt" in t for t in titles))

        # High-risk web vulnerabilities
        self.assertTrue(any("Directory Indexing / Listing Enabled" in t for t in titles))
        self.assertTrue(any("Critical CORS Misconfiguration" in t for t in titles))
        self.assertTrue(any("Cookie Missing HttpOnly Flag" in t for t in titles))
        self.assertTrue(any("Unencrypted HTTP Transport" in t for t in titles))
        self.assertTrue(any("HTTP TRACE Method Enabled" in t for t in titles))

    def test_stress_auditor_triggers_rate_limiting(self):
        target_url = f"http://127.0.0.1:{self.port}"
        # Send 18 requests when max burst is 10
        auditor = StressAuditor(target_url, num_requests=18, concurrency=4)
        findings = auditor.run()
        titles = [f.title for f in findings]
        self.assertTrue(any("Rate Limiting Enforced" in t for t in titles))

    def test_reporter_scoring_and_exports(self):
        target = f"http://127.0.0.1:{self.port}"
        reporter = Reporter(target)

        auditor = WebAuditor(target)
        findings = auditor.run()
        reporter.add_findings(findings)

        summary = reporter.calculate_risk_summary()
        self.assertGreater(summary["overall_score"], 0)
        self.assertGreater(summary["total_findings"], 0)

        # Verify findings are sorted from highest to lowest severity
        sorted_findings = reporter.get_sorted_findings()
        order_ranks = [SEVERITY_ORDER.get(f.severity.upper(), 5) for f in sorted_findings]
        self.assertEqual(order_ranks, sorted(order_ranks))

        # Test JSON and Markdown exports
        reporter.export_json("test_output.json")
        reporter.export_markdown("test_output.md")


if __name__ == "__main__":
    unittest.main()
