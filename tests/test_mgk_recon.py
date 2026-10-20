"""Tests run against a local HTTP server — no external network."""
import http.server
import json
import threading
import unittest

from mgk_recon.fetch import fetch, FetchResult
from mgk_recon.fingerprint import fingerprint
from mgk_recon.posture import posture, score
from mgk_recon.dossier import build, to_markdown


class LocalSite(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.endswith("/wp-login.php"):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"wp-login")
            return
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/final")
            self.end_headers()
            return
        if self.path == "/final":
            self.send_response(200)
            self.send_header("Server", "nginx/1.24")
            self.send_header("X-Powered-By", "Express")
            self.send_header("Strict-Transport-Security", "max-age=63072000")
            self.end_headers()
            self.wfile.write(b'<html><body><script id="__NEXT_DATA__" type="application/json">{}</script></body></html>')
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, *args):
        pass


def setUpModule():
    global BASE, server, thread
    server = http.server.HTTPServer(("127.0.0.1", 0), LocalSite)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    BASE = f"http://127.0.0.1:{server.server_address[1]}"


def tearDownModule():
    server.shutdown()


class TestFetch(unittest.TestCase):
    def test_headers_captured(self):
        result = fetch(f"{BASE}/final")
        self.assertEqual(result.status, 200)
        self.assertEqual(result.headers.get("Server"), "nginx/1.24")

    def test_redirect_chain_recorded(self):
        result = fetch(f"{BASE}/redirect")
        self.assertEqual(len(result.redirect_chain), 1)
        self.assertEqual(result.redirect_chain[0]["status"], 302)
        self.assertEqual(result.final_url, f"{BASE}/final")

    def test_error_is_evidence_not_crash(self):
        result = fetch("http://127.0.0.1:1/nope", timeout=2)
        self.assertEqual(result.status, 0)
        self.assertTrue(result.error)


class TestFingerprint(unittest.TestCase):
    def test_header_signatures_found(self):
        result = fetch(f"{BASE}/final")
        claims = [e.claim for e in fingerprint(result)]
        self.assertIn("nginx/1.24", claims)
        self.assertIn("Express", claims)

    def test_body_marker_found(self):
        result = fetch(f"{BASE}/final")
        claims = [e.claim for e in fingerprint(result)]
        self.assertTrue(any("Next" in c for c in claims))

    def test_path_probe(self):
        result = fetch(f"{BASE}/final")
        probe = lambda url: fetch(url) if url.endswith("wp-login.php") else FetchResult(url=url, final_url=url, status=0)
        claims = [e.claim for e in fingerprint(result, probe=probe)]
        self.assertTrue(any("WordPress" in c for c in claims))

    def test_every_claim_carries_source(self):
        result = fetch(f"{BASE}/final")
        for evidence in fingerprint(result):
            self.assertTrue(evidence.source)


class TestPosture(unittest.TestCase):
    def test_present_and_missing_split(self):
        result = fetch(f"{BASE}/final")
        present, missing = posture(result)
        self.assertTrue(any("HSTS" in e.claim for e in present))
        self.assertTrue(any("Content-Security-Policy" in e.claim for e in missing))

    def test_score(self):
        self.assertEqual(score(3, 5), 0.6)
        self.assertEqual(score(0, 0), 0.0)


class TestDossier(unittest.TestCase):
    def test_markdown_round_trip(self):
        dossier = build(fetch(f"{BASE}/final"))
        markdown = to_markdown(dossier)
        self.assertIn("Recon dossier", markdown)
        self.assertIn("_evidence:", markdown)

    def test_json_is_serializable(self):
        dossier = build(fetch(f"{BASE}/final"))
        json.dumps(dossier)


if __name__ == "__main__":
    unittest.main()
