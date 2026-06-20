# WebSecScope v2 / v2.1 Upgrade Plan

## Goal

WebSecScope v2 upgrades the original rule-based security scanner into a cleaner reporting tool with bilingual output, OWASP classification, improved HTTP interpretation, and a stronger HTML report.

WebSecScope v2.1 adds optional AI narrative reporting through local Ollama. The AI layer is not a detector.

WebSecScope v2.2 focuses on release readiness: settings separation, pytest coverage, documentation cleanup, and maintainability.

## Implemented in v2.0

### Korean / English Reports

- CLI supports `--lang ko` and `--lang en`.
- Default language is `ko`.
- JSON and HTML reports include `language`.
- Findings support localized `title`, `description`, `recommendation`, and `severity_label`.

### HTML Report UI

- Security Score gauge.
- Severity-specific cards.
- Executive Summary cards.
- Category and OWASP summary sections.
- Structure prepared for before/after comparison.

### HTTP Status Interpretation

Sensitive path checks distinguish:

- `200`: exposed
- `401` / `403`: protected but exists
- `404`: not found
- `301` / `302`: redirected, with `Location` recorded
- `500`: server error risk

Evidence and interpretation are stored separately so a `403` is not treated as a confirmed vulnerability by itself.

### OWASP Top 10 Classification

Each finding includes `owasp_category`.

Default examples:

- Missing CSP: `A05 Security Misconfiguration`
- Missing X-Frame-Options: `A05 Security Misconfiguration`
- Sensitive path exposure: `A05 Security Misconfiguration`
- Weak auth/session findings: `A07 Identification and Authentication Failures`
- Vulnerable dependency/CVE findings: `A06 Vulnerable and Outdated Components`

## Implemented in v2.1

### Ollama AI Report

- Uses local Ollama endpoint: `http://localhost:11434/api/generate`.
- Uses model: `qwen2.5:7b`.
- Receives only rule-based scan JSON.
- Generates only:
  - `Executive Summary`
  - `Risk Analysis`
  - `Priority Recommendations`
- Appends an `AI Report` section to HTML reports.
- Keeps JSON and HTML report generation working when Ollama fails.

## Implemented in v2.2

### Settings Separation

- Ollama URL, model, timeout, and temperature moved to `websecscope/config/settings.py`.
- Environment variables can override defaults:
  - `WEBSECSCOPE_OLLAMA_URL`
  - `WEBSECSCOPE_OLLAMA_MODEL`
  - `WEBSECSCOPE_OLLAMA_TIMEOUT`
  - `WEBSECSCOPE_OLLAMA_TEMPERATURE`

### Tests and Release Readiness

- Pytest test suite added under `tests/`.
- Tests avoid external network and real Ollama dependencies.
- README and architecture documentation updated for study and maintenance.

## Compatibility

- Existing `scan`, `report`, and `recheck` commands remain available.
- Existing JSON keys such as `findings`, `all_findings`, and section-specific finding arrays remain available.
- v2 and v2.1 add fields and sections without removing v1 report fields.

## Future Extensions

- Configurable LLM provider and endpoint.
- Optional standalone AI narrative artifact.
- Broader localized finding text coverage.
- Expanded before/after comparison visualization.
- More precise CPE-based CVE matching.
