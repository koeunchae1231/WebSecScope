from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path

from websecscope.analyzer.recheck import compare_results
from websecscope.reporter import write_html_report, write_json_report
from websecscope.scanner import run_scan
from websecscope.utils import load_json, save_json


def main() -> None:
    parser = argparse.ArgumentParser(prog="WebSecScope", description="WebSecScope v1.0 MVP security diagnostic CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Run safe security checks and save JSON results")
    scan_parser.add_argument("--target", required=True, help="Authorized target URL, e.g. https://example.com")
    scan_parser.add_argument("--output", default=None, help="Output JSON path")
    api_auth_group = scan_parser.add_mutually_exclusive_group()
    api_auth_group.add_argument("--api-auth", action="store_true", help="Include API/Auth analysis; enabled by default")
    api_auth_group.add_argument("--skip-api-auth", action="store_true", help="Skip API/Auth analysis")
    service_group = scan_parser.add_mutually_exclusive_group()
    service_group.add_argument("--service-detect", action="store_true", help="Include service/version detection; enabled by default")
    service_group.add_argument("--skip-service-detect", action="store_true", help="Skip service/version detection")
    cve_group = scan_parser.add_mutually_exclusive_group()
    cve_group.add_argument("--cve", action="store_true", help="Include NVD CVE/CVSS lookup; enabled by default")
    cve_group.add_argument("--skip-cve", action="store_true", help="Skip NVD CVE/CVSS lookup")
    linux_group = scan_parser.add_mutually_exclusive_group()
    linux_group.add_argument("--linux", action="store_true", help="Include Linux security checks; enabled by default")
    linux_group.add_argument("--skip-linux", action="store_true", help="Skip Linux security checks")
    docker_group = scan_parser.add_mutually_exclusive_group()
    docker_group.add_argument("--docker", action="store_true", help="Include Docker security checks; enabled by default")
    docker_group.add_argument("--skip-docker", action="store_true", help="Skip Docker security checks")

    report_parser = subparsers.add_parser("report", help="Generate an HTML report from a JSON result")
    report_parser.add_argument("--input", required=True, help="Input JSON result path")
    report_parser.add_argument("--output", default=None, help="Output HTML path")

    recheck_parser = subparsers.add_parser("recheck", help="Compare two JSON scan results")
    recheck_parser.add_argument("--before", required=True, help="Previous JSON result path")
    recheck_parser.add_argument("--after", required=True, help="Current JSON result path")
    recheck_parser.add_argument("--output", default="reports/recheck.json", help="Output comparison JSON path")

    args = parser.parse_args()
    try:
        if args.command == "scan":
            _scan(
                args.target,
                args.output,
                include_api_auth=not args.skip_api_auth,
                include_linux=not args.skip_linux,
                include_docker=not args.skip_docker,
                include_service_detect=not args.skip_service_detect,
                include_cve=not args.skip_cve,
            )
        elif args.command == "report":
            _report(args.input, args.output)
        elif args.command == "recheck":
            _recheck(args.before, args.after, args.output)
    except KeyboardInterrupt:
        print("Operation cancelled.")


def _scan(
    target: str,
    output: str | None,
    include_api_auth: bool = True,
    include_linux: bool = True,
    include_docker: bool = True,
    include_service_detect: bool = True,
    include_cve: bool = True,
) -> None:
    result = run_scan(
        target,
        include_api_auth=include_api_auth,
        include_linux=include_linux,
        include_docker=include_docker,
        include_service_detect=include_service_detect,
        include_cve=include_cve,
    )
    output_path = output or f"reports/result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    path = write_json_report(result, output_path)
    print(f"JSON report written: {path}")
    print(f"Security Score: {result.score}")


def _report(input_path: str, output: str | None) -> None:
    result = _safe_load_json(input_path)
    if result is None:
        return
    output_path = output or str(Path(input_path).with_suffix(".html"))
    try:
        path = write_html_report(result, output_path)
    except OSError as exc:
        print(f"HTML report failed: {type(exc).__name__}: unable to write {output_path}")
        return
    print(f"HTML report written: {path}")


def _recheck(before_path: str, after_path: str, output_path: str) -> None:
    before = _safe_load_json(before_path)
    after = _safe_load_json(after_path)
    if before is None or after is None:
        return
    comparison = compare_results(before, after)
    try:
        path = save_json(output_path, comparison)
    except OSError as exc:
        print(f"Recheck comparison failed: {type(exc).__name__}: unable to write {output_path}")
        return
    print(f"Recheck comparison written: {path}")
    print(f"Score delta: {comparison.get('score_delta')}")


def _safe_load_json(path: str) -> dict | None:
    try:
        return load_json(path)
    except FileNotFoundError:
        print(f"Input JSON not found: {path}")
    except json.JSONDecodeError:
        print(f"Input JSON is not valid: {path}")
    except OSError as exc:
        print(f"Input JSON could not be read: {path} ({type(exc).__name__})")
    return None
