"""Command-line interface for pin-deep."""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict

from .core import GitHubFetcher, Scanner, __version__


def format_text(findings) -> str:
    if not findings:
        return "pin-deep: no unpinned nested actions found. All clear."
    lines = []
    for f in findings:
        lines.append(f"[{f.status}] depth={f.depth} {f.uses}")
        lines.append(f"    source: {f.source}")
        if len(f.chain) > 1:
            lines.append("    chain:  " + "  ->  ".join(f.chain))
        if f.note:
            lines.append(f"    note:   {f.note}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="pin-deep",
        description="Recursively check GitHub Actions pins: flag unpinned "
                    "`uses:` references nested inside your SHA-pinned actions.")
    ap.add_argument("targets", nargs="+",
                    help="workflow files, action.yml files, or bare `uses:` "
                         "values like owner/repo@<sha>")
    ap.add_argument("--max-depth", "-d", type=int, default=3,
                    help="how deep to recurse into pinned actions (default: 3)")
    ap.add_argument("--format", "-f", choices=["text", "json"], default="text",
                    help="output format (default: text)")
    ap.add_argument("--strict", action="store_true",
                    help="also exit 1 on short-sha pins and fetch errors")
    ap.add_argument("--token", default=None,
                    help="GitHub token (or set GITHUB_TOKEN) for API fallback")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    scanner = Scanner(fetcher=GitHubFetcher(token=args.token),
                      max_depth=args.max_depth)
    for target in args.targets:
        if os.path.isfile(target):
            scanner.scan_file(target)
        else:
            scanner.scan_ref(target, source="<cli>")
    findings = scanner.findings
    if args.format == "json":
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        print(format_text(findings))
    unpinned = [f for f in findings if f.status == "unpinned"]
    warnings = [f for f in findings if f.status in ("short-sha", "error")]
    if unpinned or (args.strict and warnings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
