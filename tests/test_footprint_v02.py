import unittest

from mgk_recon.footprint import footprint
from mgk_recon.diffdossier import diff, diff_markdown

RESOLVED = {"name": "x", "aliases": [], "ips": ["1.2.3.4"]}


class TestFootprint(unittest.TestCase):
    def test_mixed_resolution_summary(self):
        fp = footprint(
            "example.test",
            subdomains=["a.example.test", "b.example.test", "c.example.test"],
            resolve=lambda n: RESOLVED if n.startswith("a.") else (RESOLVED if n.startswith("b.") else None),
        )
        self.assertEqual(fp["summary"]["known"], 3)
        self.assertEqual(fp["summary"]["live"], 2)
        self.assertEqual(fp["summary"]["dead"], 1)
        self.assertIsNone(fp["subdomains"]["c.example.test"])

    def test_shared_host_detection(self):
        fp = footprint(
            "example.test",
            subdomains=["a.example.test", "b.example.test"],
            resolve=lambda n: RESOLVED,
        )
        shared = fp["summary"]["shared_hosts"]
        self.assertEqual(len(shared), 1)
        self.assertIn("a.example.test", list(shared.values())[0])

    def test_no_shared_host_when_ips_differ(self):
        def r(n):
            return {"name": n, "aliases": [], "ips": ["1.1.1.1"] if n.startswith("a") else ["2.2.2.2"]}
        fp = footprint("example.test",
                       subdomains=["a.example.test", "b.example.test"], resolve=r)
        self.assertEqual(fp["summary"]["shared_hosts"], {})


class TestDiff(unittest.TestCase):
    OLD = {"technologies": [{"claim": "nginx/1.24", "source": "HTTP header Server"}],
           "security_headers": {"present": [{"claim": "HSTS enabled (max-age=63072000)", "source": "h"}],
                                 "missing": []},
           "final_url": "https://x.test/"}
    NEW = {"technologies": [{"claim": "nginx/1.25", "source": "HTTP header Server"},
                            {"claim": "React (client-rendered)", "source": "body"}],
           "security_headers": {"present": [{"claim": "HSTS enabled (max-age=63072000)", "source": "h"}],
                                "missing": [{"claim": "No Content-Security-Policy header", "source": "absent"}]},
           "final_url": "https://www.x.test/"}

    def test_technology_changes(self):
        r = diff(self.OLD, self.NEW)
        self.assertEqual(r["technologies"]["removed"], ["nginx/1.24"])
        self.assertEqual(r["technologies"]["added"], ["nginx/1.25", "React (client-rendered)"])

    def test_posture_regression(self):
        r = diff(self.OLD, self.NEW)
        self.assertIn("No Content-Security-Policy header", r["security_headers"]["added"])

    def test_redirect_change(self):
        self.assertIn("redirect_changed", diff(self.OLD, self.NEW))

    def test_no_change_report(self):
        md = diff_markdown(diff(self.OLD, dict(self.OLD)), "x.test")
        self.assertIn("No changes", md)


if __name__ == "__main__":
    unittest.main()
