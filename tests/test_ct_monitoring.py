import unittest

from mgk_recon.ct_monitoring import fetch_ct_certs, ct_diff


class TestCTMonitoring(unittest.TestCase):
    def test_fetch_ct_certs_valid_json(self):
        fake_rows = [
            {
                "id": 101,
                "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
                "not_before": "2026-01-01T00:00:00",
                "name_value": "example.com\nwww.example.com",
                "serial_number": "00a1b2c3",
            }
        ]
        certs = fetch_ct_certs("example.com", fetch_fn=lambda url: fake_rows)
        self.assertEqual(len(certs), 1)
        self.assertEqual(certs[0]["id"], 101)
        self.assertEqual(certs[0]["issuer"], "C=US, O=Let's Encrypt, CN=R3")

    def test_fetch_ct_certs_empty_array(self):
        certs = fetch_ct_certs("example.com", fetch_fn=lambda url: [])
        self.assertEqual(certs, [])

    def test_fetch_ct_certs_malformed_json(self):
        certs = fetch_ct_certs("example.com", fetch_fn=lambda url: "<html>Error 502</html>")
        self.assertEqual(certs, [])

    def test_fetch_ct_certs_network_exception(self):
        def bad_fetch(url):
            raise TimeoutError("connection timed out")

        certs = fetch_ct_certs("example.com", fetch_fn=bad_fetch)
        self.assertEqual(certs, [])

    def test_ct_diff_detects_new_certs(self):
        baseline = [
            {
                "id": 101,
                "issuer": "Let's Encrypt",
                "not_before": "2026-01-01",
                "name_value": "example.com",
                "serial_number": "s1",
            }
        ]
        current = [
            {
                "id": 101,
                "issuer": "Let's Encrypt",
                "not_before": "2026-01-01",
                "name_value": "example.com",
                "serial_number": "s1",
            },
            {
                "id": 102,
                "issuer": "DigiCert",
                "not_before": "2026-05-01",
                "name_value": "api.example.com",
                "serial_number": "s2",
            },
        ]
        new_certs = ct_diff(baseline, current)
        self.assertEqual(len(new_certs), 1)
        self.assertEqual(new_certs[0]["issuer"], "DigiCert")
        self.assertEqual(new_certs[0]["not_before"], "2026-05-01")
        self.assertEqual(new_certs[0]["name_value"], "api.example.com")
        self.assertEqual(new_certs[0]["source"], "crt.sh CT-log monitoring")

    def test_ct_diff_no_new_certs(self):
        baseline = [
            {"id": 1, "issuer": "X", "not_before": "2026-01-01", "name_value": "a.com", "serial_number": "1"}
        ]
        current = [
            {"id": 1, "issuer": "X", "not_before": "2026-01-01", "name_value": "a.com", "serial_number": "1"}
        ]
        self.assertEqual(ct_diff(baseline, current), [])


if __name__ == "__main__":
    unittest.main()
