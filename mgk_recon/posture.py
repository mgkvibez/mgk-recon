"""Security header posture analysis, evidence per finding."""
from .fetch import Evidence

SECURITY_HEADERS = {
    "strict-transport-security": {
        "label": "HSTS",
        "present": "HSTS enabled ({value})",
        "missing": "No HSTS header — transport downgrade possible",
    },
    "content-security-policy": {
        "label": "CSP",
        "present": "Content-Security-Policy set ({value})",
        "missing": "No Content-Security-Policy header — injection risk unmitigated",
    },
    "x-frame-options": {
        "label": "XFO",
        "present": "X-Frame-Options: {value}",
        "missing": "No X-Frame-Options — clickjacking protection absent",
    },
    "x-content-type-options": {
        "label": "XCTO",
        "present": "X-Content-Type-Options: {value}",
        "missing": "No X-Content-Type-Options — MIME sniffing possible",
    },
    "referrer-policy": {
        "label": "Referrer-Policy",
        "present": "Referrer-Policy: {value}",
        "missing": "No Referrer-Policy header",
    },
}


def posture(result):
    """Return (present, missing) Evidence lists for security headers."""
    headers = {k.lower(): v for k, v in result.headers.items()}
    present, missing = [], []

    for header, spec in SECURITY_HEADERS.items():
        value = headers.get(header)
        if value:
            present.append(Evidence(
                claim=spec["present"].format(value=value),
                source=f"HTTP header {header}"))
        else:
            missing.append(Evidence(
                claim=spec["missing"],
                source=f"absent from response headers ({result.final_url})"))

    return present, missing


def score(present_count, total):
    """Simple posture score: share of expected headers present."""
    return round(present_count / total, 2) if total else 0.0
