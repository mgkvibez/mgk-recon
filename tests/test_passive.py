import unittest
from mgk_recon.fetch import FetchResult
from mgk_recon.passive import (
    check_security_txt,
    check_email_security,
    check_tls_cert,
    passive_checks,
    RULESET_VERSION,
)


class TestPassiveChecks(unittest.TestCase):
    def test_security_txt_present_well_known(self):
        def fake_fetch(url):
            if "/.well-known/security.txt" in url:
                return FetchResult(
                    url=url,
                    final_url=url,
                    status=200,
                    body_excerpt="Contact: mailto:security@example.com\nContact: https://example.com/bounty\nExpires: 2027-01-01\n",
                )
            return FetchResult(url=url, final_url=url, status=404)

        results = check_security_txt("https://example.com", fetch_fn=fake_fetch)
        self.assertEqual(len(results), 1)
        self.assertIn("present at /.well-known/security.txt", results[0].claim)
        self.assertIn("2 Contact line(s)", results[0].claim)
        self.assertEqual(results[0].source, "GET /.well-known/security.txt (HTTP 200)")

    def test_security_txt_present_root(self):
        def fake_fetch(url):
            if url.endswith("/security.txt") and not url.endswith("/.well-known/security.txt"):
                return FetchResult(
                    url=url,
                    final_url=url,
                    status=200,
                    body_excerpt="Contact: security@example.com\n",
                )
            return FetchResult(url=url, final_url=url, status=404)

        results = check_security_txt("https://example.com", fetch_fn=fake_fetch)
        self.assertEqual(len(results), 1)
        self.assertIn("present at /security.txt", results[0].claim)
        self.assertIn("1 Contact line(s)", results[0].claim)

    def test_security_txt_absent(self):
        def fake_fetch(url):
            return FetchResult(url=url, final_url=url, status=404)

        results = check_security_txt("https://example.com", fetch_fn=fake_fetch)
        self.assertEqual(len(results), 1)
        self.assertIn("absent", results[0].claim)

    def test_email_security_dmarc_and_spf_present(self):
        def fake_resolve_txt(domain):
            if domain == "_dmarc.example.com":
                return ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]
            if domain == "example.com":
                return ["v=spf1 include:_spf.google.com ~all"]
            return []

        results = check_email_security("example.com", resolve_txt=fake_resolve_txt)
        self.assertEqual(len(results), 2)
        self.assertIn("DMARC record present", results[0].claim)
        self.assertEqual(results[0].source, "DNS TXT _dmarc.example.com")
        self.assertIn("SPF record present", results[1].claim)
        self.assertEqual(results[1].source, "DNS TXT example.com")

    def test_email_security_absent(self):
        def fake_resolve_txt(domain):
            return []

        results = check_email_security("example.com", resolve_txt=fake_resolve_txt)
        self.assertEqual(len(results), 2)
        self.assertIn("No DMARC TXT record found", results[0].claim)
        self.assertIn("No SPF TXT record found", results[1].claim)

    def test_tls_cert_summary_success(self):
        class FakeSocket:
            def getpeercert(self):
                return {
                    "subject": ((("commonName", "example.com"),),),
                    "issuer": ((("organizationName", "Let's Encrypt"),), (("commonName", "R3"),)),
                    "notBefore": "Jan  1 00:00:00 2026 GMT",
                    "notAfter": "Apr  1 00:00:00 2026 GMT",
                }

        results = check_tls_cert("example.com", socket_factory=lambda host, port, timeout=5: FakeSocket())
        self.assertEqual(len(results), 3)
        self.assertIn("TLS cert Subject CN: example.com", results[0].claim)
        self.assertIn("TLS cert Issuer: Let's Encrypt, R3", results[1].claim)
        self.assertIn("Jan  1 00:00:00 2026 GMT to Apr  1 00:00:00 2026 GMT", results[2].claim)

    def test_tls_cert_summary_failure(self):
        def bad_factory(host, port, timeout=5):
            raise ConnectionRefusedError("Connection refused")

        results = check_tls_cert("example.com", socket_factory=bad_factory)
        self.assertEqual(len(results), 1)
        self.assertIn("TLS certificate check failed", results[0].claim)

    def test_ruleset_wording_no_word_safe(self):
        res = passive_checks("https://example.com", resolve_txt=lambda d: [], fetch_fn=lambda u: FetchResult(url=u, final_url=u, status=404), socket_factory=lambda h, p, timeout=5: None)
        self.assertEqual(res["ruleset"], "v0.3.0")
        self.assertIn("no issues found by ruleset v0.3.0", res["advisory"])
        # Verify word "safe" is NOT present anywhere in res dictionary or string representations
        s = str(res).lower()
        self.assertNotIn("safe", s)


if __name__ == "__main__":
    unittest.main()
