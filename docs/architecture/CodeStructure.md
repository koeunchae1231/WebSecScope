# WebSecScope Code Structure

This document explains how the WebSecScope codebase is organized and how a scan becomes a JSON or HTML report.

## Big Picture

```text
main.py
  -> websecscope.cli
    -> scanner.orchestrator.run_scan()
      -> scanner modules collect evidence
      -> analyzer modules create findings
      -> models.ScanResult normalizes output
    -> reporter.json_reporter writes JSON
    -> reporter.html_reporter writes HTML
      -> reporter.llm_report_generator optionally asks Ollama for AI summary
        -> config.settings supplies Ollama defaults and environment overrides
```

WebSecScope is intentionally rule-based. Scanners and analyzers create findings. The LLM layer only summarizes existing findings.

## `main.py`

`main.py` is the smallest entry point.

It imports `main` from `websecscope.cli` and runs it:

```python
from websecscope.cli import main

if __name__ == "__main__":
    main()
```

When you run this command:

```bash
python main.py scan --target https://example.com
```

Python starts in `main.py`, then immediately moves into the CLI module.

## `websecscope/cli.py`

`cli.py` owns the command-line interface.

It defines three user-facing commands:

- `scan`: run scanners and save JSON.
- `report`: turn JSON into HTML.
- `recheck`: compare two JSON scan results.

It also owns CLI options such as:

- `--target`
- `--output`
- `--lang ko`
- `--lang en`
- `--skip-linux`
- `--skip-docker`
- `--skip-cve`

The CLI should stay thin. It should parse options, call the right workflow, and print useful paths or errors.

## `websecscope/scanner/`

Scanner modules collect evidence. They should avoid making final security claims.

Examples:

- `web.py`: checks HTTP headers, cookies, reachability, and sensitive paths.
- `api_scanner.py`: probes safe API/auth candidate paths.
- `auth_scanner.py`: collects authentication-related response signals.
- `linux_scanner.py`: collects read-only Linux host data.
- `docker_scanner.py`: collects read-only Docker container data.
- `service_detector.py`: collects listening service information.
- `version_detector.py`: tries to normalize product/version data.

Scanners answer questions like:

- What HTTP status was returned?
- Which header was present?
- Which port is listening?
- Which Docker container option was observed?

They should not invent vulnerability narratives. That job belongs to analyzers.

## `websecscope/scanner/orchestrator.py`

`orchestrator.py` coordinates the scan workflow.

It calls scanner modules, passes raw evidence to analyzer modules, calculates the score, and returns a `ScanResult`.

This is the main scan pipeline:

```text
run_scan(target)
  -> scan_web_target(target)
  -> optional API/auth scans
  -> optional Linux scan
  -> optional service/version detection
  -> optional Docker scan
  -> optional CVE lookup
  -> calculate_score(findings)
  -> ScanResult(...)
```

If you want to understand the full scan flow, start with `run_scan()`.

## `websecscope/analyzer/`

Analyzer modules turn evidence into findings.

Examples:

- `api_auth_analyzer.py`: API/auth/JWT/CORS/IDOR/rate-limit findings.
- `linux_analyzer.py`: Linux hardening findings.
- `docker_analyzer.py`: Docker runtime hardening findings.
- `service_analyzer.py`: risky service exposure and service inventory findings.
- `cve.py`: NVD CVE/CVSS advisory findings.
- `score.py`: security score calculation.
- `recheck.py`: before/after comparison.

A finding includes fields such as:

- `check_id`
- `category`
- `title`
- `status`
- `risk`
- `evidence`
- `recommendation`
- `metadata`

Analyzers should keep evidence and interpretation separate when possible.

## `websecscope/models.py`

`models.py` defines the core data structures:

- `Finding`
- `ScanResult`

`Finding.to_dict()` adds normalized report fields:

- `id`
- `severity`
- `severity_label`
- `description`
- `interpretation`
- `owasp_category`
- `language`

`ScanResult.to_dict()` builds the final JSON shape used by both JSON and HTML reports.

## `websecscope/reporter/`

Reporter modules write output files.

### `json_reporter.py`

Writes `ScanResult.to_dict()` to a JSON file.

### `html_reporter.py`

Builds a single-file HTML report from result JSON.

Important rendering helpers include:

- `render_score_gauge`
- `render_severity_cards`
- `render_findings_sections`
- `render_ai_report_section`

The HTML report shows:

- Executive Summary
- Security Score
- Severity summary
- Top risks
- Category and OWASP summaries
- Web/API/Linux/Docker/Service/CVE sections
- All findings
- Optional AI Report

### `llm_report_generator.py`

This module prepares and optionally calls the LLM report layer.

It is deliberately not a scanner.

Important functions:

- `build_prompt`: creates the Korean or English prompt.
- `call_ollama`: calls the configured LLM client.
- `build_success_report`: normalizes successful output.
- `build_fallback_report`: normalizes Ollama failure.
- `generate_llm_report`: high-level function used by the HTML reporter.

Only selected rule-based JSON fields are sent to Ollama.

## `websecscope/config/`

The config package keeps runtime settings out of feature code.

`websecscope/config/settings.py` defines defaults and environment-variable overrides for the AI Report integration:

- `OLLAMA_URL`
- `OLLAMA_MODEL`
- `OLLAMA_TIMEOUT`
- `OLLAMA_TEMPERATURE`

Supported environment variables:

- `WEBSECSCOPE_OLLAMA_URL`
- `WEBSECSCOPE_OLLAMA_MODEL`
- `WEBSECSCOPE_OLLAMA_TIMEOUT`
- `WEBSECSCOPE_OLLAMA_TEMPERATURE`

The LLM reporter imports these settings, so Ollama configuration can change without editing reporter logic.

## `websecscope/i18n.py`

`i18n.py` owns language-related resources.

It includes:

- supported language codes
- severity labels
- report UI text
- selected finding translations
- recommendation translations

The default language is Korean:

```text
ko
```

English is selected with:

```bash
--lang en
```

## `websecscope/owasp.py`

`owasp.py` maps findings to OWASP Top 10 categories.

Examples:

- Web security headers -> `A05 Security Misconfiguration`
- Sensitive path exposure -> `A05 Security Misconfiguration`
- Authentication/session findings -> `A07 Identification and Authentication Failures`
- CVE findings -> `A06 Vulnerable and Outdated Components`

The mapping is intentionally simple and rule-based.

## How To Study The Code

Recommended order:

1. Read `main.py`.
2. Read `websecscope/cli.py`.
3. Read `run_scan()` in `scanner/orchestrator.py`.
4. Read one scanner, such as `scanner/web.py`.
5. Read the matching analyzer logic.
6. Read `models.py` to understand final JSON fields.
7. Read `reporter/html_reporter.py`.
8. Read `reporter/llm_report_generator.py`.
9. Read `config/settings.py`.
10. Read the files in `tests/` to see expected behavior.

This order follows the same path as a real command execution.

## Tests

The `tests/` directory contains pytest tests for the most important maintenance boundaries:

- `test_http_status.py`: sensitive-path HTTP interpretation.
- `test_score.py`: security score and grade behavior.
- `test_owasp.py`: OWASP Top 10 mapping.
- `test_i18n.py`: language normalization and labels.
- `test_llm_report_generator.py`: LLM prompt safety, success path, fallback path, and settings overrides.
