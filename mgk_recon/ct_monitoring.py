"""Certificate transparency monitoring module (crt.sh).

Maintains baseline certificate sets per domain and diffs current certs
against baseline to report potential-change events.
"""
import json
import urllib.request
import urllib.error


def fetch_ct_certs(domain, fetch_fn=None, timeout=15):
    """Fetch certificate set for a domain from crt.sh.

    Tolerates malformed JSON, empty arrays, and network errors gracefully.
    `fetch_fn` is injectable for offline tests.
    """
    url = f"https://crt.sh/?q={domain}&output=json"
    if fetch_fn is not None:
        try:
            data = fetch_fn(url)
            if isinstance(data, list):
                return _normalize_certs(data)
            if isinstance(data, (str, bytes)):
                rows = json.loads(data)
                if isinstance(rows, list):
                    return _normalize_certs(rows)
                return []
            return []
        except Exception:
            return []

    req = urllib.request.Request(url, headers={"User-Agent": "mgk-recon/0.3"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            rows = json.loads(raw)
            if isinstance(rows, list):
                return _normalize_certs(rows)
            return []
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError, OSError, ValueError):
        return []


def _normalize_certs(rows):
    certs = []
    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        issuer = str(row.get("issuer_name") or "")
        not_before = str(row.get("not_before") or "")
        name_val = str(row.get("name_value") or "")
        serial = str(row.get("serial_number") or row.get("id") or "")

        key = (serial, issuer, not_before, name_val)
        if key in seen:
            continue
        seen.add(key)

        certs.append({
            "id": row.get("id"),
            "issuer": issuer,
            "not_before": not_before,
            "name_value": name_val,
            "serial_number": serial,
        })
    return certs


def ct_diff(baseline_certs, current_certs):
    """Diff current crt.sh cert set against a saved baseline.

    Returns list of NEW certs (issuer, not-before date, name match)
    as potential-change events.
    """
    baseline_keys = {
        (c.get("serial_number") or c.get("id"), c.get("issuer"), c.get("not_before"), c.get("name_value"))
        for c in (baseline_certs or [])
    }

    new_certs = []
    for c in (current_certs or []):
        key = (c.get("serial_number") or c.get("id"), c.get("issuer"), c.get("not_before"), c.get("name_value"))
        if key not in baseline_keys:
            new_certs.append({
                "claim": f"New certificate: Issuer={c.get('issuer')}, NotBefore={c.get('not_before')}, Names={c.get('name_value')}",
                "issuer": c.get("issuer"),
                "not_before": c.get("not_before"),
                "name_value": c.get("name_value"),
                "serial_number": c.get("serial_number"),
                "source": "crt.sh CT-log monitoring",
            })
    return new_certs
