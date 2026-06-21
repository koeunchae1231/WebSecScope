# WebSecScope (WSS)

WebSecScope is a defensive, rule-based security diagnostic CLI for web applications, Linux hosts, Docker environments, service/version inventory, CVE/CVSS review, and JSON/HTML report generation.

Important v2.2 note: the Ollama/Qwen2.5 AI Report is optional. The LLM is treated as a report formatter, not a security decision maker. Findings, severity, evidence, and recommendations are produced by the rule-based scanner/analyzer pipeline and score calculator.

The AI Report Formatter receives only scanner-approved rule-based JSON fields. Raw HTTP responses, debug logs, internal exception text, and console output are excluded from AI input. The AI prompt expects a JSON formatter schema, and model output is validated and sanitized before rendering. If the model output does not match the expected schema, WebSecScope falls back to scanner-derived text instead of trusting freeform AI output.

## Quick Start

Install dependencies:

```bash
pip install -r requirements.txt
```

Run a scan and create a report:

```bash
python main.py scan --target https://example.com --output reports/result.json
python main.py report --input reports/result.json --output reports/result.html
```

English report:

```bash
python main.py scan --target https://example.com --lang en --output reports/result_en.json
python main.py report --input reports/result_en.json --lang en --output reports/result_en.html
```

Recheck comparison:

```bash
python main.py recheck --before reports/before.json --after reports/result.json --output reports/recheck.json
```

Optional AI Report Formatter with Ollama:

```bash
ollama pull qwen2.5:7b
ollama serve
python main.py report --input reports/result.json --output reports/result.html
```

## Implementation Status

### v1.0

- Rule-based web security checks.
- API/auth heuristic analysis.
- Linux and Docker read-only checks.
- Service/version detection.
- NVD CVE/CVSS lookup.
- Security score and grade.
- JSON and HTML report generation.
- Recheck comparison.

### v2.0

- Korean/English report language support with `--lang ko` and `--lang en`.
- `language` included in JSON and HTML reports.
- Localized severity labels and report text structure.
- OWASP Top 10 classification with `owasp_category` on findings.
- Improved sensitive-path HTTP status interpretation:
  - `200`: exposed
  - `401` / `403`: protected but exists
  - `404`: not found
  - `301` / `302`: redirected, with `Location` recorded
  - `500`: server error risk
- Evidence and interpretation separated in finding output.
- Improved HTML report UI with score gauge, severity cards, executive summary cards, and category/OWASP sections.

### v2.1

- Optional Ollama AI Report integration.
- Model: `qwen2.5:7b`.
- Endpoint: `http://localhost:11434/api/generate`.
- AI output sections:
  - `Executive Summary`
  - `Risk Analysis`
  - `Priority Recommendations`
- Graceful fallback when Ollama is unavailable or fails.
- The LLM receives only rule-based scan JSON and never modifies `all_findings`.

### v2.2

- Ollama settings moved into `websecscope/config/settings.py`.
- Ollama endpoint, model, timeout, and temperature override through environment variables.
- AI Report Formatter reliability improvement.
- JSON schema-based AI output validation.
- Markdown/internal message sanitizing.
- Scanner-derived fallback text when AI output is invalid or freeform.
- Korean localization cleanup.
- HTML report readability redesign.
- Security Score explanation and improved Executive Summary.
- Top-risk detail cards and Detailed Finding cards.
- Top-risk detail field support in the summary model.
- Updated tests for AI validation/fallback/sanitizing and report behavior.
- py_compile passed.
- pytest 20 passed.

## CLI Options

### `scan`

```bash
python main.py scan --target https://example.com --lang ko --output reports/result.json
```

Common options:

- `--target`: authorized target URL.
- `--output`: JSON output path.
- `--lang {ko,en}`: report language, default `ko`.
- `--skip-api-auth`: skip API/auth analysis.
- `--skip-linux`: skip Linux checks.
- `--skip-docker`: skip Docker checks.
- `--skip-service-detect`: skip service/version detection.
- `--skip-cve`: skip NVD CVE/CVSS lookup.

### `report`

```bash
python main.py report --input reports/result.json --output reports/result.html
```

Common options:

- `--input`: input JSON result path.
- `--output`: HTML output path.
- `--lang {ko,en}`: override report language.

### `recheck`

```bash
python main.py recheck --before reports/before.json --after reports/result.json
```

## Report Outputs

JSON reports include:

- `language`
- `score` and `grade`
- `findings_summary`
- `findings` and `all_findings`
- localized `title`, `description`, `recommendation`, and `severity_label`
- `owasp_category`
- `evidence`
- `interpretation`

HTML reports include:

- Security Score explanation.
- Executive Summary.
- Severity cards.
- Top Risk cards.
- Detailed Finding cards.
- Category/OWASP sections.
- Web, API/Auth, Service, CVE, Linux, and Docker sections.
- Optional AI Report Formatter section.

## Sample Reports

Sample reports generated during verification:

- [Korean AI sample](docs/samples/sample_v2_ko_ai.html)
- [English AI sample](docs/samples/sample_v2_en_ai.html)

The matching sample JSON files are:

- `reports/sample_v2_ko.json`
- `reports/sample_v2_en.json`

## Ollama AI Report Formatter

Install and run Ollama locally:

```bash
ollama pull qwen2.5:7b
ollama serve
```

Then generate the normal rule-based JSON and HTML report:

```bash
python main.py scan --target https://example.com --lang ko --output reports/result.json
python main.py report --input reports/result.json --output reports/result.html
```

The AI Report Formatter section is appended to the end of the HTML report. It includes this notice:

```text
Findings were detected by the rule-based engine. The LLM only summarized and explained the results.
```

AI Report Formatter guardrails:

- The LLM is not a vulnerability detector.
- The LLM receives only scanner-approved rule-based fields.
- Raw HTTP responses, debug logs, and internal exception text are excluded.
- The prompt expects a JSON formatter schema.
- AI output is validated and sanitized before HTML rendering.
- Markdown markers, HTML, and internal error messages are removed or ignored.
- Invalid schema or freeform output triggers scanner-derived fallback text.
- Ollama failure does not block the rule-based JSON/HTML report.

### AI Report Configuration

Default settings:

- `OLLAMA_URL`: `http://localhost:11434/api/generate`
- `OLLAMA_MODEL`: `qwen2.5:7b`
- `OLLAMA_TIMEOUT`: `60`
- `OLLAMA_TEMPERATURE`: `0.2`

Override with environment variables:

Windows PowerShell:

```powershell
$env:WEBSECSCOPE_OLLAMA_MODEL = "qwen2.5:7b"
$env:WEBSECSCOPE_OLLAMA_TIMEOUT = "90"
python main.py report --input reports/result.json --output reports/result.html
```

Linux / macOS:

```bash
export WEBSECSCOPE_OLLAMA_MODEL=qwen2.5:7b
export WEBSECSCOPE_OLLAMA_TIMEOUT=90
python main.py report --input reports/result.json --output reports/result.html
```

Supported override variables:

- `WEBSECSCOPE_OLLAMA_URL`
- `WEBSECSCOPE_OLLAMA_MODEL`
- `WEBSECSCOPE_OLLAMA_TIMEOUT`
- `WEBSECSCOPE_OLLAMA_TEMPERATURE`

## Testing

Run the test suite:

```bash
pytest
```

The tests do not require external network access or a running Ollama process.

Current verification status:

- py_compile passed.
- pytest 20 passed.

## Release Tags

Recommended GitHub release tags:

- `v1.0.0`: first rule-based MVP.
- `v2.0.0`: bilingual reports, OWASP classification, improved HTML report, HTTP status interpretation.
- `v2.1.0`: optional Ollama/Qwen2.5 AI Report.
- `v2.2.0`: AI Report Formatter reliability, schema validation, sanitizing, scanner-derived fallback, Korean localization cleanup, HTML report readability redesign, tests, and docs.

## Safety

WebSecScope is designed for authorized defensive review.

- No brute force.
- No denial-of-service testing.
- No exploit execution.
- No destructive filesystem or container actions.
- Docker and Linux checks are read-only.
- CVE matches are advisory and should be manually verified.

## Code Structure

See [docs/architecture/CodeStructure.md](docs/architecture/CodeStructure.md) for a beginner-friendly explanation of the code flow.

## Requirements

- Python 3.10 or newer recommended.
- Optional: Docker CLI access for Docker checks.
- Optional: Linux runtime for Linux checks.
- Optional: `NVD_API_KEY` for better NVD API rate limits.
- Optional: Ollama with `qwen2.5:7b` for AI Report Formatter generation.

## License

MIT License.
