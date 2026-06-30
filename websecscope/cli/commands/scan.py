from __future__ import annotations

import argparse
from datetime import datetime

from websecscope.i18n import DEFAULT_LANGUAGE, SUPPORTED_LANGUAGES, normalize_language
from websecscope.reporter import write_json_report
from websecscope.scanner import run_scan


def add_scan_parser(subparsers: argparse._SubParsersAction) -> None:
    scan_parser = subparsers.add_parser("scan", help="Run safe security checks and save JSON results")
    scan_parser.add_argument("--target", required=True, help="Authorized target URL, e.g. https://example.com")
    scan_parser.add_argument("--output", default=None, help="Output JSON path")
    scan_parser.add_argument("--lang", choices=sorted(SUPPORTED_LANGUAGES), default=DEFAULT_LANGUAGE, help="Report language: ko or en")
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
    scan_parser.set_defaults(handler=run_scan_command)


def run_scan_command(args: argparse.Namespace) -> None:
    result = run_scan(
        args.target,
        language=normalize_language(args.lang),
        include_api_auth=not args.skip_api_auth,
        include_linux=not args.skip_linux,
        include_docker=not args.skip_docker,
        include_service_detect=not args.skip_service_detect,
        include_cve=not args.skip_cve,
    )
    output_path = args.output or f"reports/result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    path = write_json_report(result, output_path, language=args.lang)
    print(f"JSON report written: {path}")
    print(f"Security Score: {result.score}")
