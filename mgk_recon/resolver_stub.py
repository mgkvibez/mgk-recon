"""Resolution layer, injectable for tests (same shape as
perimeter-watch's resolver, kept local so the skill stays self-contained)."""
import socket


def resolve(name, timeout=5):
    try:
        _name, aliases, ips = socket.gethostbyname_ex(name)
    except (socket.gaierror, TimeoutError, OSError):
        return None
    return {"name": name, "aliases": [a.lower() for a in aliases], "ips": sorted(ips)}


def resolve_txt(name, timeout=5):
    """Resolve TXT records for a domain. Injectable for tests.

    The stdlib resolver exposes no TXT lookups, so this shells out to
    host/dig/nslookup in turn; any failure (missing tool, timeout,
    NXDOMAIN) returns [] rather than raising - passive checks stay
    advisory and never break a dossier run.
    """
    import shutil
    import subprocess

    for tool, cmd in (("host", ["host", "-t", "TXT", name]),
                      ("dig", ["dig", "+short", "TXT", name]),
                      ("nslookup", ["nslookup", "-type=TXT", name])):
        if shutil.which(tool) is None:
            continue
        try:
            res = subprocess.run(cmd, capture_output=True, text=True,
                                 timeout=timeout)
        except Exception:
            continue
        if res.returncode != 0:
            continue
        txts = []
        for line in res.stdout.splitlines():
            marker = "descriptive text" if tool == "host" else None
            if marker and marker in line:
                txts.append(line.split(marker, 1)[1].strip().strip('"'))
            elif tool == "dig" and line.strip():
                txts.append(line.strip().strip('"'))
            elif tool == "nslookup" and '"' in line:
                txts.append(line.split('"')[1])
        if txts or " NXDOMAIN " not in res.stdout:
            return txts
    return []
