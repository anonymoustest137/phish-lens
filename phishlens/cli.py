"""phish-lens CLI."""
import argparse
import json
import sys

from . import __version__
from .scorer import score

BAR = 34
COLOR = {"phishing": "\033[31m", "suspicious": "\033[33m", "likely_safe": "\033[32m"}
RESET = "\033[0m"


def main():
    ap = argparse.ArgumentParser(prog="phish-lens",
                                 description="Explainable phishing scorer")
    ap.add_argument("-u", "--url", help="URL to analyze")
    ap.add_argument("-f", "--file", help="email body file ('-' for stdin)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args()

    text = None
    if args.file == "-":
        text = sys.stdin.read()
    elif args.file:
        with open(args.file, encoding="utf-8", errors="ignore") as fh:
            text = fh.read()

    if not args.url and not text:
        ap.error("provide --url and/or --file")

    result = score(args.url, text)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    filled = int(result["score"] / 100 * BAR)
    c = COLOR.get(result["verdict"], "")
    print("phish-lens v" + __version__)
    if args.url:
        print("target: " + args.url)
    print("[" + "#" * filled + "." * (BAR - filled) + "] " +
          str(result["score"]) + "/100")
    print("verdict: " + c + result["verdict"].upper() + RESET + "\n")
    if result["reasons"]:
        print("why:")
        for r in result["reasons"]:
            print("  - " + r)
    else:
        print("no suspicious indicators found")


if __name__ == "__main__":
    main()
