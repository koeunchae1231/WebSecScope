from __future__ import annotations

import argparse

from websecscope.cli.commands.common import safe_load_json
from websecscope.comparison import compare_results
from websecscope.utils import save_json


def add_recheck_parser(subparsers: argparse._SubParsersAction) -> None:
    recheck_parser = subparsers.add_parser("recheck", help="Compare two JSON scan results")
    recheck_parser.add_argument("--before", required=True, help="Previous JSON result path")
    recheck_parser.add_argument("--after", required=True, help="Current JSON result path")
    recheck_parser.add_argument("--output", default="reports/recheck.json", help="Output comparison JSON path")
    recheck_parser.set_defaults(handler=run_recheck_command)


def run_recheck_command(args: argparse.Namespace) -> None:
    before = safe_load_json(args.before)
    after = safe_load_json(args.after)
    if before is None or after is None:
        return
    comparison = compare_results(before, after)
    try:
        path = save_json(args.output, comparison)
    except OSError as exc:
        print(f"Recheck comparison failed: {type(exc).__name__}: unable to write {args.output}")
        return
    print(f"Recheck comparison written: {path}")
    print(f"Score delta: {comparison.get('score_delta')}")
