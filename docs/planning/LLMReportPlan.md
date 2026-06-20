# LLM Report Plan

## Purpose

The LLM report layer turns rule-based scan results into a narrative explanation. It helps readers understand the result, but it does not detect vulnerabilities.

## Non-Goals

The LLM must not:

- Add new findings.
- Change severity.
- Invent CVEs, endpoints, evidence, or recommendations.
- Treat inconclusive evidence as confirmed.
- Perform active scanning.
- Modify `all_findings` or any machine-readable finding list.

## Data Flow

```text
Scanner / Analyzer
  -> Rule-based ScanResult JSON
  -> Safe LLM payload
  -> Ollama prompt
  -> Optional narrative AI Report section
```

Only selected rule-based JSON keys are sent to the LLM. The prompt explicitly says that detection has already been performed by the rule-based engine.

## Implemented v2.1 Interface

Module:

```text
websecscope.reporter.llm_report_generator
```

Main objects and functions:

- `LLMReportRequest`: holds rule-based JSON, language, model, and endpoint.
- `OllamaClient`: calls the local Ollama API.
- `build_prompt(request)`: builds a Korean or English prompt.
- `build_llm_prompt(request)`: compatibility wrapper for `build_prompt`.
- `call_ollama(client, prompt, model)`: isolates the provider call.
- `build_success_report(...)`: normalizes successful AI output.
- `build_fallback_report(...)`: normalizes graceful fallback output.
- `generate_llm_report(request, client=None)`: returns either AI content or fallback metadata.

## Ollama Settings

- Endpoint: `http://localhost:11434/api/generate`
- Model: `qwen2.5:7b`
- Streaming: disabled
- Temperature: `0.2`
- Timeout: `60` seconds

In v2.2, these values are defined in `websecscope/config/settings.py` and can be overridden by environment variables:

- `WEBSECSCOPE_OLLAMA_URL`
- `WEBSECSCOPE_OLLAMA_MODEL`
- `WEBSECSCOPE_OLLAMA_TIMEOUT`
- `WEBSECSCOPE_OLLAMA_TEMPERATURE`

## HTML Integration

`html_reporter.py` calls `generate_llm_report()` while rendering the HTML report.

If Ollama succeeds, the final `AI Report` section contains:

- `Executive Summary`
- `Risk Analysis`
- `Priority Recommendations`

If Ollama fails, the same section shows a fallback message and the regular report still works.

## Future Extensions

- User-configurable model, endpoint, and timeout.
- Optional standalone AI report artifact.
- Additional provider adapters behind the same `LLMClient` protocol.
- UI toggle for including or skipping AI report generation.
