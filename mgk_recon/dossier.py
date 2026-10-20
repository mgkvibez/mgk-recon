"""Dossier assembly: markdown + JSON, every claim source-linked."""
import datetime as dt

from .fingerprint import fingerprint
from .posture import posture, score


def build(result, probe=None):
    """Assemble the dossier dict for a fetched result."""
    tech = fingerprint(result, probe=probe)
    present, missing = posture(result)
    present_count = len(present)
    total = present_count + len(missing)

    return {
        "target": result.url,
        "final_url": result.final_url,
        "fetched_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "status": result.status,
        "error": result.error or None,
        "redirect_chain": result.redirect_chain,
        "technologies": [e.to_dict() for e in tech],
        "security_headers": {
            "present": [e.to_dict() for e in present],
            "missing": [e.to_dict() for e in missing],
            "score": score(present_count, total),
        },
    }


def to_markdown(dossier):
    """Render a dossier dict as a human-readable markdown report."""
    lines = [f"# Recon dossier — {dossier['target']}", ""]
    lines.append(f"_Fetched {dossier['fetched_at']}; final URL: {dossier['final_url']}"
                 f" (status {dossier['status']})")
    if dossier["error"]:
        lines.append(f"\n> fetch error: {dossier['error']}")
    lines.append("")

    if dossier["redirect_chain"]:
        lines.append("## Redirect chain")
        for hop in dossier["redirect_chain"]:
            lines.append(f"- {hop['from']} → {hop['to']} ({hop['status']})")
        lines.append("")

    lines.append("## Detected technologies")
    if dossier["technologies"]:
        for t in dossier["technologies"]:
            lines.append(f"- **{t['claim']}** — _evidence: {t['source']}_")
    else:
        lines.append("- none detected")
    lines.append("")

    sec = dossier["security_headers"]
    lines.append(f"## Security header posture (score {sec['score']})")
    for h in sec["present"]:
        lines.append(f"- ✔ {h['claim']} — _evidence: {h['source']}_")
    for h in sec["missing"]:
        lines.append(f"- ✘ {h['claim']} — _evidence: {h['source']}_")
    lines.append("")
    lines.append("_Passive and OSINT-legal techniques only. Every claim carries its source._")
    return "\n".join(lines)
