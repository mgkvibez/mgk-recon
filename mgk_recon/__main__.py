"""CLI: python -m mgk_recon example.com [--out dossier.md]"""
import argparse
import json
import sys

from .fetch import fetch
from .dossier import build, to_markdown


def main(argv=None):
    parser = argparse.ArgumentParser(prog="mgk_recon",
                                     description="Evidence-based recon dossier for a domain")
    parser.add_argument("target", help="domain or full URL to profile")
    parser.add_argument("--out", default=None, help="write markdown dossier to this path")
    parser.add_argument("--json", dest="json_out", default=None, help="write JSON dossier to this path")
    parser.add_argument("--footprint", action="store_true",
                        help="include the DNS/subdomain hosting footprint (CT-log enumeration)")
    parser.add_argument("--diff", dest="diff_with", default=None,
                        help="path to a previous JSON dossier; report what changed")
    parser.add_argument("--passive", action="store_true",
                        help="include strictly passive checks (security.txt, DMARC/SPF, TLS cert summary)")
    parser.add_argument("--ct-baseline", dest="ct_baseline", default=None,
                        help="record the current CT-log certificate set to this JSON path")
    parser.add_argument("--ct-diff", dest="ct_diff_path", default=None,
                        help="compare the current CT-log cert set against a saved baseline JSON")
    args = parser.parse_args(argv)

    target = args.target if args.target.startswith("http") else f"https://{args.target}"
    target_host = args.target.split("/")[0] if args.target.startswith("http") else args.target
    result = fetch(target)
    dossier = build(result)

    if args.diff_with:
        import json as _json
        with open(args.diff_with, encoding="utf-8") as fh:
            previous = _json.load(fh)
        from .diffdossier import diff, diff_markdown
        print(diff_markdown(diff(previous, dossier), target_host))
        return 0

    sections = []

    if args.footprint:
        from .footprint import footprint
        fp = footprint(target_host)
        dossier["footprint"] = fp
        sections.append("\n## Hosting footprint\n" + _footprint_md(fp))

    if args.passive:
        from .passive import passive_checks
        pc = passive_checks(target)
        dossier["passive_checks"] = pc
        sections.append("\n## Passive checks\n" + _passive_md(pc))

    if args.ct_baseline:
        from .ct_monitoring import fetch_ct_certs
        certs = fetch_ct_certs(target_host)
        with open(args.ct_baseline, "w", encoding="utf-8") as fh:
            json.dump(certs, fh, indent=2)
        print(f"CT baseline recorded: {len(certs)} certificates -> {args.ct_baseline}")

    if args.ct_diff_path:
        from .ct_monitoring import fetch_ct_certs, ct_diff
        with open(args.ct_diff_path, encoding="utf-8") as fh:
            baseline = json.load(fh)
        new_certs = ct_diff(baseline, fetch_ct_certs(target_host))
        dossier["ct_new_certs"] = new_certs
        sections.append("\n## CT monitoring\n" +
                        (_ct_md(new_certs) if new_certs
                         else "_no new certificates since the baseline_"))

    markdown = to_markdown(dossier) + "".join(sections)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(markdown + "\n")
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(dossier, fh, indent=2)

    if not args.out:
        print(markdown)
    if dossier["error"]:
        print(f"\nwarning: fetch reported: {dossier['error']}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())


def _footprint_md(fp):
    s = fp["summary"]
    lines = [f"\n_{s['live']} of {s['known']} CT-log subdomains live_"]
    for ips, names in s["shared_hosts"].items():
        lines.append(f"- shared host ({ips}): " + ", ".join(names))
    return "\n".join(lines)


def _passive_md(pc):
    lines = [f"\n_{pc['advisory']}_"]
    for section in ("security_txt", "email_security", "tls_cert"):
        for e in pc[section]:
            lines.append(f"- **{e['claim']}** — _evidence: {e['source']}_")
        if not pc[section]:
            label = section.replace("_", " ")
            lines.append(f"- no {label} evidence by ruleset {pc['ruleset']}")
    return "\n".join(lines)


def _ct_md(new_certs):
    lines = []
    for c in new_certs:
        lines.append(f"- **{c['claim']}** — _evidence: {c['source']}_")
    return "\n".join(lines)
