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

    if args.footprint:
        from .footprint import footprint
        fp = footprint(target_host)
        dossier["footprint"] = fp
        markdown = to_markdown(dossier) + "\n## Hosting footprint\n" + _footprint_md(fp)
    else:
        markdown = to_markdown(dossier)
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
