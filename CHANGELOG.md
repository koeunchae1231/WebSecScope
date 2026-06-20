# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project follows semantic versioning for release labeling.

## [1.0.0] - 2026-06-19

### Added

- Web Security Header Scan
- API and Authentication Analysis
- JWT, CORS, IDOR, and Rate Limit analysis
- Service Detection and Version Detection
- NVD CVE API 2.0 lookup
- CVSS severity normalization
- Linux Security Scan
- Docker Security Scan
- Security Score and Grade
- Findings Summary and Top Risks
- JSON and HTML report generation
- Recheck comparison
- Read-only safety model
- CLI skip options for API/Auth, Service Detection, CVE, Linux, and Docker scans
- GitHub Actions compile check workflow

### Changed

- Unified finding schema across modules
- Consolidated scanner and analyzer responsibilities
- Improved score calculation with confidence and skipped scan handling
- Improved HTML report readability for portfolio review

### Fixed

- Safe skipped handling for non-Linux environments
- Safe skipped handling for missing Docker CLI or unavailable Docker daemon
- Safe JSON input handling for missing or invalid report files
- Recheck compatibility with older result formats where possible

### Security

- Read-only checks only
- No brute force behavior
- No authentication bypass behavior
- No destructive Docker commands
- No system configuration changes

### Notes

- First MVP release for authorized web services, Linux hosts, and Docker environments.
- Built with the Python standard library, `argparse`, `urllib`, JSON output, and single-file HTML output.
- Linux host checks provide the most complete coverage when WebSecScope runs on a Linux environment.
- Docker checks are skipped when Docker CLI is missing or Docker daemon access is unavailable.
- CVE matches are potentially related advisory findings and require manual verification.

### Deferred

- Package version inventory.
- More precise CPE-based CVE relevance scoring.
- Expanded SSH configuration parsing.
- Firewall rule detail review.
- Category-level score.
- Recheck-focused HTML layout improvements.
