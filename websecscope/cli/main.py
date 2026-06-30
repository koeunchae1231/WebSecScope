from __future__ import annotations

import argparse

from websecscope.cli.commands.recheck import add_recheck_parser
from websecscope.cli.commands.report import add_report_parser
from websecscope.cli.commands.scan import add_scan_parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.handler(args)
    except KeyboardInterrupt:
        print("Operation cancelled.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="WebSecScope",
        description="WebSecScope v1.0 MVP security diagnostic CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    add_scan_parser(subparsers)
    add_report_parser(subparsers)
    add_recheck_parser(subparsers)
    return parser
