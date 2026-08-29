#!/usr/bin/env python3
"""Extract IPs/CIDRs from a Cloudflare rule expression and write an IP List CSV."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

IP_TOKEN = re.compile(
    r"""
    (?:
        (?:[\d]{1,3}\.){3}[\d]{1,3}(?:/\d{1,2})?
        |
        [0-9a-fA-F:]+(?:/\d{1,3})?
    )
    """,
    re.VERBOSE,
)


def extract(expression: str) -> list[str]:
    tokens: list[str] = []
    seen: set[str] = set()

    for raw in IP_TOKEN.findall(expression):
        token = raw.strip().rstrip(",;")
        if not token or token.lower() in {"http", "https"}:
            continue
        if "." not in token and ":" not in token:
            continue
        if token.count(".") == 3 or ":" in token:
            if token not in seen:
                seen.add(token)
                tokens.append(token)
    return tokens


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Convert a BLOCK_BOTS expression into a Cloudflare IP List CSV."
    )
    parser.add_argument(
        "expression_file",
        nargs="?",
        help="Text file containing the copied rule expression. Reads stdin if omitted.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="jail_list.csv",
        help="CSV path (default: jail_list.csv)",
    )
    parser.add_argument(
        "-c",
        "--comment",
        default="migrated from BLOCK_BOTS",
        help="Optional comment column",
    )
    args = parser.parse_args()

    if args.expression_file:
        text = Path(args.expression_file).read_text(encoding="utf-8")
    else:
        text = sys.stdin.read()

    items = extract(text)
    if not items:
        print("No IP addresses or CIDRs found in the expression.", file=sys.stderr)
        return 1

    out = Path(args.output)
    lines = [f"{item},{args.comment}" for item in items]
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {len(items)} row(s) to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
