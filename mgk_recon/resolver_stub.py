"""Resolution layer, injectable for tests (same shape as
perimeter-watch's resolver, kept local so the skill stays self-contained)."""
import socket


def resolve(name, timeout=5):
    try:
        _name, aliases, ips = socket.gethostbyname_ex(name)
    except (socket.gaierror, TimeoutError, OSError):
        return None
    return {"name": name, "aliases": [a.lower() for a in aliases], "ips": sorted(ips)}
