# WebSecScope (WSS)

WebSecScope는 Web Application, Linux host, Docker 환경, service/version inventory, CVE/CVSS 검토, JSON/HTML report 생성을 위한 방어형 rule-based 보안 진단 CLI.

v2.2 기준 AI Report는 선택 기능. LLM은 취약점 탐지기나 보안 의사결정자가 아니라 Report Formatter. Finding, severity, evidence, recommendation은 scanner/analyzer와 score calculator가 생성한 rule-based 결과만 근거.

AI Report Formatter는 scanner/analyzer가 생성한 rule-based JSON 중 허용된 field만 입력으로 사용. raw HTTP response, debug log, internal exception text, console output은 AI 입력에서 제외. AI 출력은 JSON schema 중심 prompt, validation, sanitizing을 거친 뒤 HTML에 렌더링. 모델이 schema를 지키지 않거나 freeform 응답을 반환하는 경우 scanner-derived fallback text 사용.

영문 문서: [README_EN.md](README_EN.md)

## 프로젝트 소개

WebSecScope의 목표는 반복 가능한 보안 점검 결과를 읽기 쉬운 JSON/HTML report로 정리하는 것.

주요 설계 방향:

- 공격 도구가 아닌 방어형 진단 도구
- exploit 실행 없는 read-only 중심 점검
- scanner와 analyzer가 만든 evidence 기반 finding
- score, OWASP, recommendation, recheck 결과를 포함한 report 중심 구조
- LLM이 탐지하지 않고 scanner/analyzer 결과를 설명하는 선택형 AI Report Formatter 구조
- AI 출력 validation, Markdown/internal text sanitizing, scanner-derived fallback 기반 신뢰성 보강

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
- Optional Ollama AI Report Formatter
- AI output validation
- Markdown/internal text sanitizing
- Scanner-derived fallback report
- Improved Korean HTML report readability
- Top-risk detail cards

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

Ollama 기반 Optional AI Report Formatter:

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
- CVE lookup rate limit 완화를 위한 선택형 `NVD_API_KEY`
- AI Report Formatter 사용 시 Ollama 및 `qwen2.5:7b`

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

- Security Score explanation
- Executive Summary
- Severity cards
- Top Risk cards
- Detailed Finding cards
- Category/OWASP sections
- Web / API/Auth / Service / CVE / Linux / Docker sections
- Optional AI Report Formatter section

## Sample Reports

검증 과정에서 생성한 sample report:

- [Korean AI sample](docs/samples/sample_v2_ko_ai.html)
- [English AI sample](docs/samples/sample_v2_en_ai.html)

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
- AI Report Formatter reliability improvement
- JSON schema-based AI output validation
- Markdown/internal message sanitizing
- AI output invalid 시 scanner-derived fallback text 사용
- Korean localization cleanup
- HTML report readability redesign
- Security Score explanation 및 Executive Summary 개선
- Top-risk detail cards 및 Detailed Finding cards 추가
- Top-risk detail field support
- HTTP status, score, OWASP, i18n, AI validation/fallback/sanitizing 관련 pytest 업데이트
- py_compile 통과
- pytest 20 passed

## Ollama AI Report Formatter

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

HTML report 마지막에 Optional AI Report Formatter section 추가. 해당 section의 안내문:

```text
Findings were detected by the rule-based engine. The LLM only summarized and explained the results.
```

AI Report Formatter 안전장치:

- LLM은 취약점 탐지자가 아닌 report formatter
- scanner/analyzer가 생성한 rule-based JSON 중 허용 field만 AI 입력으로 전달
- raw HTTP response, debug log, internal exception text 제외
- AI prompt는 JSON formatter schema 중심
- AI output validation 및 sanitizing 적용
- Markdown marker, HTML, 내부 오류 메시지 노출 방지
- schema 불일치 또는 freeform 응답 시 scanner-derived fallback text 사용
- Ollama 실패 시에도 rule-based JSON/HTML report 생성 유지

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

상세 code flow와 module 역할 문서:

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
- HTTP status interpretation, score, OWASP, i18n, AI report validation/fallback/sanitizing 관련 테스트
- 현재 기준 pytest 20 passed

## Roadmap

완료:

- `v1.0.0`: rule-based MVP
- `v2.0.0`: bilingual report, OWASP classification, HTTP status interpretation, HTML UI 개선
- `v2.1.0`: optional Ollama/Qwen2.5 AI Report
- `v2.2.0`: AI Report Formatter reliability, output validation/sanitizing, scanner-derived fallback, Korean localization cleanup, HTML readability redesign

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
