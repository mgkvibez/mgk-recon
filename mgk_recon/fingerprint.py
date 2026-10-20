"""Technology fingerprinting: every match cites its evidence.

Signatures are deliberately conservative: a match requires a positive
signal, and the signal text is carried into the dossier.
"""
from .fetch import Evidence

HTTP_SIGNATURES = [
    ("Server", "server-header", lambda v: v),
    ("X-Powered-By", "x-powered-by", lambda v: v),
]

BODY_SIGNATURES = [
    ("WordPress", '<meta name="generator" content="WordPress'),
    ("Drupal", '<meta name="generator" content="Drupal'),
    ("React (client-rendered)", 'data-reactroot'),
    ("Next.js", '__NEXT_DATA__'),
    ("Nuxt", '__NUXT__'),
    ("Angular", 'ng-version'),
    ("Laravel (session cookie)", "laravel_session"),
    ("PHP (default session cookie)", "PHPSESSID"),
    ("Cloudflare", "cdn-cgi/challenge-platform"),
]

PATH_PROBES = [
    ("WordPress", "/wp-login.php", 200),
    ("WordPress REST API", "/wp-json/", 200),
]


def fingerprint(result, probe=None):
    """Return Evidence records for detected technologies.

    `probe` is an injectable fetch callable (tests pass a stub) used
    for the PATH_PROBES; None disables path probing.
    """
    found, seen = [], set()

    def add(claim, source):
        if claim not in seen:
            seen.add(claim)
            found.append(Evidence(claim=claim, source=source))

    headers = {k.lower(): v for k, v in result.headers.items()}

    for header, _label, _fmt in HTTP_SIGNATURES:
        value = headers.get(header.lower())
        if value:
            add(value, f"HTTP header {header}")

    lowered = result.body_excerpt.lower()
    for tech, marker in BODY_SIGNATURES:
        if marker.lower() in lowered:
            add(tech, f"response body marker {marker!r}")

    if probe:
        for tech, path, expected in PATH_PROBES:
            probe_result = probe(result.final_url + path)
            if probe_result.status == expected:
                add(tech, f"GET {path} returned {expected}")

    return found
