# WebSecScope v1.0 Release Notes

## Overview

WebSecScope v1.0 is the first MVP release of a Python-based security diagnostic CLI for authorized web services, Linux hosts, and Docker environments.

The release focuses on read-only evidence collection, rule-based analysis, JSON/HTML reporting, and before/after recheck comparison.

## Major Features

- Web Security Header Scan
- API and Authentication Analysis
- JWT structure review
- CORS policy analysis
- IDOR heuristic review
- Rate limit signal check
- Service Detection and Version Detection
- NVD CVE API 2.0 lookup
- CVSS-based severity normalization
- Linux Security Scan
- Docker Security Scan
- Security Score and Grade
- Findings Summary and Top Risks
- JSON Report
- HTML Report
- Recheck comparison

## Technology Stack

- Python standard library
- argparse CLI
- urllib-based HTTP requests
- JSON result format
- Single-file HTML report
- NVD CVE API 2.0
- Linux read-only filesystem checks
- Docker CLI read-only inspection

## Key Improvements

- Modular scanner, analyzer, guide, reporter, and visualizer structure
- Unified finding schema with id, title, severity, category, description, evidence, and recommendation
- Score calculation with severity, confidence, skipped scan, and duplicate finding handling
- Environment-aware Linux and Docker skipped states
- Safe handling for network errors, NVD failures, missing Docker daemon, non-Linux runtime, and unreadable JSON input
- Recheck result with score delta, grade delta, resolved findings, new findings, unchanged findings, and severity delta

## Known Limitations

- Windows environments may show Linux Scan as skipped.
- Docker Scan is skipped when Docker CLI is missing or Docker daemon is not reachable.
- Linux environments provide the most complete host-level scan coverage.
- CVE matches are potentially related findings and require manual verification.
- Package inventory, category score, historical trend, and chart visualization are not included in v1.0.

## Roadmap for v1.1

- Package version inventory
- More precise CPE-based CVE relevance scoring
- Expanded SSH configuration parsing
- Firewall rule detail review
- Category-level score
- Recheck-focused HTML layout improvements
