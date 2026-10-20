"""DNS/subdomain hosting footprint — passive sources only.

Enumerates subdomains via certificate transparency (crt.sh), resolves
them with the standard library, and fingerprints the hosting layer
from what resolution alone reveals. No active scanning.
"""
import json
import urllib.request

from .resolver_stub import resolve as _default_resolve


def ct_subdomains(domain, timeout=15):
    """Certificate-transparency subdomain discovery (crt.sh)."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "mgk-recon/0.2"})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        rows = json.load(response)
    found = set()
    for row in rows:
        for name in (row.get("name_value") or "").splitlines():
            name = name.strip().lower().rstrip(".")
            if name.endswith("." + domain) and "*" not in name:
                found.add(name)
    return sorted(found)


def footprint(domain, subdomains=None, resolve=None, timeout=15):
    """Resolve subdomains and assemble the hosting footprint.

    Returns {subdomain: record-or-None} plus summary stats. Inject
    `subdomains`/`resolve` for offline tests.
    """
    resolve = resolve or _default_resolve
    names = subdomains if subdomains is not None else ct_subdomains(domain, timeout)

    records = {}
    for name in names:
        try:
            records[name] = resolve(name)
        except OSError:
            records[name] = None

    live = [n for n, r in records.items() if r]
    shared = {}
    for name, record in records.items():
        if record:
            key = tuple(record["ips"]) if hasattr(record, "get") else tuple(record["ips"])
            shared.setdefault(key, []).append(name)

    return {
        "domain": domain,
        "subdomains": records,
        "summary": {
            "known": len(records),
            "live": len(live),
            "dead": len(records) - len(live),
            "shared_hosts": {", ".join(k): v for k, v in shared.items() if len(v) > 1},
        },
    }
