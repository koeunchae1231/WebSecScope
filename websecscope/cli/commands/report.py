from __future__ import annotations

import argparse
from pathlib import Path

from websecscope.cli.commands.common import safe_load_json
from websecscope.i18n import SUPPORTED_LANGUAGES
from websecscope.reporter import write_html_report


def add_report_parser(subparsers: argparse._SubParsersAction) -> None:
    report_parser = subparsers.add_parser("report", help="Generate an HTML report from a JSON result")
    report_parser.add_argument("--input", required=True, help="Input JSON result path")
    report_parser.add_argument("--output", default=None, help="Output HTML path")
    report_parser.add_argument("--lang", choices=sorted(SUPPORTED_LANGUAGES), default=None, help="Override report language")
    report_parser.set_defaults(handler=run_report_command)


def run_report_command(args: argparse.Namespace) -> None:
    result = safe_load_json(args.input)
    if result is None:
        return
    output_path = args.output or str(Path(args.input).with_suffix(".html"))
    try:
        path = write_html_report(result, output_path, language=args.lang)
    except OSError as exc:
        print(f"HTML report failed: {type(exc).__name__}: unable to write {output_path}")
        return
    print(f"HTML report written: {path}")
