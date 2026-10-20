"""Dossier comparison: what changed between two scans of a domain."""


def _claims(d, key):
    """Flatten a dossier section into {claim: source}.

    Handles both shapes: flat evidence lists (technologies) and the
    security-headers block (present + missing sublists).
    """
    value = d.get(key) or []
    if isinstance(value, dict):
        entries = list(value.get("present", [])) + list(value.get("missing", []))
    else:
        entries = list(value)
    return {c["claim"]: c["source"] for c in entries}


def diff(old, new):
    """Diff two dossier dicts. Returns per-section added/removed/changed."""
    report = {}
    for key in ("technologies", "security_headers"):
        before = _claims(old, key)
        after = _claims(new, key)
        report[key] = {
            "added": [c for c in after if c not in before],
            "removed": [c for c in before if c not in after],
            "changed": [c for c in after if c in before and after[c] != before[c]],
        }

    if old.get("final_url") != new.get("final_url"):
        report["redirect_changed"] = {
            "from": old.get("final_url"), "to": new.get("final_url")
        }
    return report


def diff_markdown(report, target):
    lines = [f"## Dossier diff — {target}", ""]
    for section, label in (("technologies", "Technologies"),
                           ("security_headers", "Security posture")):
        block = report[section]
        if not any(block.values()):
            continue
        lines.append(f"### {label}")
        lines += [f"- + **{c}**" for c in block["added"]]
        lines += [f"- - ~~{c}~~" for c in block["removed"]]
        lines += [f"- ~ evidence changed: {c}" for c in block["changed"]]
        lines.append("")
    if "redirect_changed" in report:
        r = report["redirect_changed"]
        lines.append(f"- redirect target moved: {r['from']} -> {r['to']}")
    if len(lines) == 2:
        lines.append("No changes between the two dossiers.")
    return "\n".join(lines)
