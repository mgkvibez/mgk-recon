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
    args = parser.parse_args(argv)

    target = args.target if args.target.startswith("http") else f"https://{args.target}"
    result = fetch(target)
    dossier = build(result)

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
