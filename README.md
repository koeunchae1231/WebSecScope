# WebSecScope (WSS)

WebSecScope는 Web Application, Linux host, Docker 환경, service/version inventory, CVE/CVSS 검토, JSON/HTML report 생성을 위한 방어적 rule-based 보안 진단 CLI.

v2.1 이후의 Ollama/Qwen2.5 AI Report는 선택 기능. LLM은 취약점 탐지를 수행하지 않으며, finding은 scanner/analyzer 기반 rule-based pipeline에서만 생성. LLM은 이미 생성된 rule-based JSON을 요약하고 설명하는 역할.

영문 문서는 [README_EN.md](README_EN.md)에 별도 제공.

## 프로젝트 소개

WebSecScope의 목표는 반복적인 보안 점검 결과를 일관된 JSON/HTML report로 남기는 것.

주요 설계 방향:

- 공격 도구가 아닌 방어적 진단 도구
- exploit 실행 없는 read-only 중심 점검
- scanner와 analyzer가 만든 evidence 기반 finding
- score, OWASP, recommendation, recheck 결과를 포함한 report 중심 구조
- LLM이 탐지하지 않고 결과 설명만 담당하는 선택형 AI Report 구조

## 주요 기능

- Web Security Header scan
- Cookie security attribute 확인
- Sensitive path HTTP status 해석
- API/Auth heuristic analysis
- JWT/CORS/IDOR/rate-limit signal review
- Linux read-only security check
- Docker read-only security check
- Service/version detection
- NVD CVE/CVSS lookup
- Security Score 및 grade 계산
- OWASP Top 10 category 매핑
- Korean/English report 지원
- JSON/HTML report 생성
- Before/After recheck 비교
- Optional Ollama AI Report

## Quick Start

의존성 설치:

```bash
pip install -r requirements.txt
```

scan 실행 및 report 생성:

```bash
python main.py scan --target https://example.com --output reports/result.json
python main.py report --input reports/result.json --output reports/result.html
```

English report 생성:

```bash
python main.py scan --target https://example.com --lang en --output reports/result_en.json
python main.py report --input reports/result_en.json --lang en --output reports/result_en.html
```

recheck 비교:

```bash
python main.py recheck --before reports/before.json --after reports/result.json --output reports/recheck.json
```

Ollama 기반 Optional AI Report:

```bash
ollama pull qwen2.5:7b
ollama serve
python main.py report --input reports/result.json --output reports/result.html
```

## 설치

권장 환경:

- Python 3.10 이상
- Docker check 사용 시 Docker CLI 접근 권한
- Linux check 사용 시 Linux runtime
- CVE lookup 품질 향상을 위한 선택적 `NVD_API_KEY`
- AI Report 사용 시 Ollama 및 `qwen2.5:7b`

설치:

```bash
pip install -r requirements.txt
```

## 실행

### `scan`

```bash
python main.py scan --target https://example.com --lang ko --output reports/result.json
```

주요 option:

- `--target`: 승인된 target URL
- `--output`: JSON output path
- `--lang {ko,en}`: report language, 기본값 `ko`
- `--skip-api-auth`: API/Auth analysis 제외
- `--skip-linux`: Linux check 제외
- `--skip-docker`: Docker check 제외
- `--skip-service-detect`: service/version detection 제외
- `--skip-cve`: NVD CVE/CVSS lookup 제외

### `report`

```bash
python main.py report --input reports/result.json --output reports/result.html
```

주요 option:

- `--input`: input JSON result path
- `--output`: HTML output path
- `--lang {ko,en}`: report language override

### `recheck`

```bash
python main.py recheck --before reports/before.json --after reports/result.json
```

## Report Output

JSON report 주요 field:

- `language`
- `score`
- `grade`
- `findings_summary`
- `findings`
- `all_findings`
- `title`
- `description`
- `recommendation`
- `severity_label`
- `owasp_category`
- `evidence`
- `interpretation`

HTML report 주요 section:

- Security Score gauge
- Executive Summary
- Severity cards
- Top Risks
- Category and OWASP sections
- Web / API/Auth / Service / CVE / Linux / Docker sections
- All Findings table
- Optional AI Report section

## Sample Reports

검증 과정에서 생성한 sample report:

- [Korean AI sample](reports/sample_v2_ko_ai.html)
- [English AI sample](reports/sample_v2_en_ai.html)

matching sample JSON:

- `reports/sample_v2_ko.json`
- `reports/sample_v2_en.json`

## 구현 상태

### v1.0

- Rule-based web security check
- API/Auth heuristic analysis
- Linux 및 Docker read-only check
- Service/version detection
- NVD CVE/CVSS lookup
- Security Score 및 grade
- JSON/HTML report generation
- Recheck comparison

### v2.0

- `--lang ko`, `--lang en` 기반 Korean/English report 지원
- JSON/HTML report의 `language` field
- localized severity label 및 report text 구조
- finding별 `owasp_category` 추가
- Sensitive path HTTP status 해석 개선
  - `200`: exposed
  - `401` / `403`: protected but exists
  - `404`: not found
  - `301` / `302`: redirected, `Location` 기록
  - `500`: server error risk
- `evidence`와 `interpretation` 분리
- Security Score gauge, severity cards, Executive Summary cards, category/OWASP sections 기반 HTML UI 개선

### v2.1

- Optional Ollama AI Report integration
- model: `qwen2.5:7b`
- endpoint: `http://localhost:11434/api/generate`
- AI output section:
  - `Executive Summary`
  - `Risk Analysis`
  - `Priority Recommendations`
- Ollama unavailable/failure 시 graceful fallback
- LLM 입력은 rule-based scan JSON만 사용
- LLM이 `all_findings`를 수정하지 않는 구조

### v2.2

- Ollama 설정값의 `websecscope/config/settings.py` 분리
- Ollama endpoint, model, timeout, temperature 환경변수 override 지원
- HTTP status, score, OWASP, i18n, LLM fallback 대상 pytest 추가
- 유지보수성을 위한 README, docs, CodeStructure 정리

## Ollama AI Report

Ollama 설치 및 실행:

```bash
ollama pull qwen2.5:7b
ollama serve
```

일반 rule-based JSON 생성 후 HTML report 생성:

```bash
python main.py scan --target https://example.com --lang ko --output reports/result.json
python main.py report --input reports/result.json --output reports/result.html
```

HTML report 마지막에 `AI Report` section 추가. 해당 section에는 다음 안내문 포함:

```text
Findings were detected by the rule-based engine. The LLM only summarized and explained the results.
```

Ollama가 실행 중이 아니거나 요청이 실패해도 JSON/HTML report 생성은 정상 진행. AI section에는 fallback message 표시.

### AI Report 설정

기본값:

- `OLLAMA_URL`: `http://localhost:11434/api/generate`
- `OLLAMA_MODEL`: `qwen2.5:7b`
- `OLLAMA_TIMEOUT`: `60`
- `OLLAMA_TEMPERATURE`: `0.2`

환경변수 override:

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

지원 환경변수:

- `WEBSECSCOPE_OLLAMA_URL`
- `WEBSECSCOPE_OLLAMA_MODEL`
- `WEBSECSCOPE_OLLAMA_TIMEOUT`
- `WEBSECSCOPE_OLLAMA_TEMPERATURE`

## 프로젝트 구조

```text
main.py
  -> websecscope/cli.py
    -> websecscope/scanner/
    -> websecscope/analyzer/
    -> websecscope/models.py
    -> websecscope/reporter/
      -> json_reporter.py
      -> html_reporter.py
      -> llm_report_generator.py
    -> websecscope/i18n.py
    -> websecscope/owasp.py
    -> websecscope/config/settings.py
```

학습용 상세 구조 문서:

- [docs/architecture/CodeStructure.md](docs/architecture/CodeStructure.md)

## 테스트

pytest 실행:

```bash
pytest
```

테스트 특징:

- 외부 network 의존 없음
- 실제 Ollama process 의존 없음
- LLM success/fallback은 monkeypatch 기반 검증
- HTTP status interpretation, score, OWASP, i18n, LLM report generator 대상 테스트

## Roadmap

완료:

- `v1.0.0`: rule-based MVP
- `v2.0.0`: bilingual report, OWASP classification, HTTP status interpretation, HTML UI 개선
- `v2.1.0`: optional Ollama/Qwen2.5 AI Report
- `v2.2.0`: settings separation, tests, docs, release readiness cleanup

향후 확장 후보:

- configurable LLM provider
- standalone AI narrative artifact
- localized finding text coverage 확대
- before/after comparison visualization 강화
- CPE 기반 CVE matching 정확도 개선

## Safety

WebSecScope의 안전 원칙:

- brute force 없음
- denial-of-service testing 없음
- exploit execution 없음
- destructive filesystem 또는 container action 없음
- Docker 및 Linux check는 read-only 중심
- CVE match는 advisory 정보이며 수동 검증 필요

## License

MIT License.
