"""Passive security checks module — strictly non-intrusive observations.

Checks:
1. security.txt presence (/.well-known/security.txt and /security.txt) + contact count.
2. Email security records (DMARC TXT, SPF TXT) via injectable DNS resolver.
3. TLS certificate summary (Subject CN, Issuer, validity window) via stdlib ssl + injectable socket factory.

All findings returned as Evidence records with sources. Scores/wording stay advisory
('no issues found by ruleset v0.3.0').
"""
import ssl
import socket
from urllib.parse import urlparse

from .fetch import Evidence, fetch
from .resolver_stub import resolve_txt as _default_resolve_txt

RULESET_VERSION = "v0.3.0"
ADVISORY_MESSAGE = f"no issues found by ruleset {RULESET_VERSION}"


def check_security_txt(target_url, fetch_fn=None):
    """Check presence of security.txt at standard locations and count Contact: lines."""
    fetch_fn = fetch_fn or fetch
    parsed = urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else target_url.rstrip("/")

    paths = ["/.well-known/security.txt", "/security.txt"]
    for path in paths:
        url = base_url + path
        try:
            res = fetch_fn(url)
            if res and getattr(res, "status", 0) == 200 and getattr(res, "body_excerpt", None):
                contact_count = sum(
                    1 for line in res.body_excerpt.splitlines()
                    if line.strip().lower().startswith("contact:")
                )
                return [Evidence(
                    claim=f"security.txt present at {path} ({contact_count} Contact line(s))",
                    source=f"GET {path} (HTTP 200)"
                )]
        except Exception:
            continue

    return [Evidence(
        claim="security.txt absent at standard paths (/.well-known/security.txt, /security.txt)",
        source="GET /.well-known/security.txt and /security.txt (non-200 or unreachable)"
    )]


def check_email_security(domain, resolve_txt=None):
    """Check presence of DMARC and SPF TXT records for domain."""
    resolve_txt = resolve_txt or _default_resolve_txt
    evidence = []

    # DMARC lookup
    dmarc_domain = f"_dmarc.{domain}"
    try:
        dmarc_records = resolve_txt(dmarc_domain) or []
        dmarc_found = [r for r in dmarc_records if r.strip().lower().startswith("v=dmarc1")]
        if dmarc_found:
            evidence.append(Evidence(
                claim=f"DMARC record present ({dmarc_found[0]})",
                source=f"DNS TXT {dmarc_domain}"
            ))
        else:
            evidence.append(Evidence(
                claim=f"No DMARC TXT record found for {dmarc_domain}",
                source=f"DNS TXT {dmarc_domain}"
            ))
    except Exception:
        evidence.append(Evidence(
            claim=f"No DMARC TXT record found for {dmarc_domain}",
            source=f"DNS TXT {dmarc_domain}"
        ))

    # SPF lookup
    try:
        spf_records = resolve_txt(domain) or []
        spf_found = [r for r in spf_records if r.strip().lower().startswith("v=spf1")]
        if spf_found:
            evidence.append(Evidence(
                claim=f"SPF record present ({spf_found[0]})",
                source=f"DNS TXT {domain}"
            ))
        else:
            evidence.append(Evidence(
                claim=f"No SPF TXT record found for {domain}",
                source=f"DNS TXT {domain}"
            ))
    except Exception:
        evidence.append(Evidence(
            claim=f"No SPF TXT record found for {domain}",
            source=f"DNS TXT {domain}"
        ))

    return evidence


def check_tls_cert(hostname, port=443, socket_factory=None, timeout=5):
    """Retrieve TLS certificate summary for HTTPS hosts using stdlib ssl or socket_factory."""
    evidence = []
    try:
        if socket_factory is not None:
            sock = socket_factory(hostname, port, timeout=timeout)
            cert = sock.getpeercert()
        else:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=timeout) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=hostname) as sock:
                    cert = sock.getpeercert()

        if cert:
            subject_cn = "unknown"
            for rdn in cert.get("subject", ()):
                for k, v in rdn:
                    if k == "commonName":
                        subject_cn = v
                        break

            issuer_parts = []
            for rdn in cert.get("issuer", ()):
                for k, v in rdn:
                    if k in ("organizationName", "commonName"):
                        issuer_parts.append(v)
            issuer_str = ", ".join(issuer_parts) if issuer_parts else "unknown"

            not_before = cert.get("notBefore", "unknown")
            not_after = cert.get("notAfter", "unknown")

            evidence.append(Evidence(
                claim=f"TLS cert Subject CN: {subject_cn}",
                source=f"TLS handshake with {hostname}:{port}"
            ))
            evidence.append(Evidence(
                claim=f"TLS cert Issuer: {issuer_str}",
                source=f"TLS handshake with {hostname}:{port}"
            ))
            evidence.append(Evidence(
                claim=f"TLS cert validity window: {not_before} to {not_after}",
                source=f"TLS handshake with {hostname}:{port}"
            ))
        else:
            evidence.append(Evidence(
                claim="TLS certificate details unavailable",
                source=f"TLS handshake with {hostname}:{port}"
            ))
    except Exception as exc:
        evidence.append(Evidence(
            claim=f"TLS certificate check failed ({type(exc).__name__})",
            source=f"TLS handshake with {hostname}:{port}"
        ))

    return evidence


def passive_checks(target_url, fetch_fn=None, resolve_txt=None, socket_factory=None, port=443):
    """Run passive security checks and return structured evidence dictionary."""
    parsed = urlparse(target_url)
    hostname = parsed.netloc.split(":")[0] if parsed.netloc else target_url.split("/")[0]

    sec_txt = check_security_txt(target_url, fetch_fn=fetch_fn)
    email_sec = check_email_security(hostname, resolve_txt=resolve_txt)
    tls_sec = check_tls_cert(hostname, port=port, socket_factory=socket_factory)

    return {
        "ruleset": RULESET_VERSION,
        "advisory": ADVISORY_MESSAGE,
        "security_txt": [e.to_dict() for e in sec_txt],
        "email_security": [e.to_dict() for e in email_sec],
        "tls_cert": [e.to_dict() for e in tls_sec],
    }
