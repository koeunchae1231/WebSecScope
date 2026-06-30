# WebSecScope (WSS)

WebSecScope는 Web Application, Linux host, Docker 환경, service/version inventory, CVE/CVSS 결과를 JSON/HTML report로 정리하는 방어적 rule-based 보안 진단 CLI.

핵심 구조는 `Scanner -> Analyzer -> Reporter -> Optional AI Formatter` 흐름. Scanner는 관측 가능한 Evidence 생성 담당, Analyzer는 Evidence 기반 판단 담당, Reporter는 출력 담당, LLM은 탐지자가 아닌 Report Formatter 역할.

Rule-based Engine은 WebSecScope 결과의 Single Source of Truth. Finding, severity, evidence, recommendation, score는 scanner/analyzer/scoring 계층이 만든 결과 기준. LLM 결과는 rule-based 결과의 설명과 요약을 위한 선택 기능.

영문 문서: [README_EN.md](README_EN.md)

## 프로젝트 소개

WebSecScope의 목표는 반복 가능한 보안 점검 결과를 사람이 읽기 쉬운 HTML report와 기계가 처리하기 쉬운 JSON report로 정리하는 구조.

주요 설계 방향:

- 공격 도구가 아닌 방어적 진단 도구
- exploit 실행 없는 read-only 중심 점검
- Scanner가 생성한 Evidence 기반 판단
- Analyzer가 생성한 Finding 기반 Score 계산
- Reporter가 담당하는 JSON/HTML 출력
- LLM이 탐지자가 아닌 Report Formatter로만 동작하는 구조
- Rule-based 결과 우선 원칙
- Validation, Audit Trail, Benchmark, DI 확장을 위한 내부 경계

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
- OWASP Top 10 category mapping
- Korean/English report 지원
- JSON/HTML report 생성
- Before/After recheck 비교
- Optional Ollama AI Report Formatter
- AI output validation 및 sanitizing
- Scanner-derived fallback report

## Quick Start

의존성 설치:

```bash
pip install -r requirements.txt
```

scan 실행 및 JSON report 생성:

```bash
python main.py scan --target https://example.com --output reports/result.json
```

HTML report 생성:

```bash
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

Optional AI Report Formatter:

```bash
ollama pull qwen2.5:7b
ollama serve
python main.py report --input reports/result.json --output reports/result.html
```

## 프로젝트 구조

```text
websecscope/
    cli/
        main.py
        commands/
            scan.py
            report.py
            recheck.py
    scanner/
    rules/
    analyzer/
    comparison/
    scoring/
    reporter/
        html/
        json/
        ai/
    models.py
    config/
    utils.py
```

디렉터리 역할:

- `cli/`: argparse 구성 및 command dispatch 책임
- `cli/commands/`: scan, report, recheck command별 실행 책임
- `scanner/`: target과 runtime에서 관측 가능한 Evidence 수집 책임
- `rules/`: scanner가 참조하는 rule catalog와 rule metadata 기반
- `analyzer/`: Evidence 기반 Finding 판단 책임
- `comparison/`: before/after 결과 비교, delta, summary 책임
- `scoring/`: rule-based Finding 기반 score, weight, grade 계산 책임
- `reporter/`: 출력 계층 책임
- `reporter/html/`: HTML report writer 경계
- `reporter/json/`: JSON report writer 경계
- `reporter/ai/`: LLM 기반 report formatter 경계
- `models.py`: Evidence, Finding, ScanResult 등 공통 모델
- `config/`: 환경설정과 환경변수 접근 경계
- `utils.py`: 공통 파일 처리와 보조 함수

## Architecture

기본 실행 흐름:

```text
Scan
    ↓
Scanner
    ↓
Evidence 생성
    ↓
Analyzer
    ↓
Score 계산
    ↓
Reporter
    ↓
Optional AI Formatter
    ↓
HTML / JSON Report
```

역할과 책임:

- Scanner: HTTP status, header, cookie, Linux/Docker local state, service/version signal 등 관측 가능한 Evidence 생성
- Analyzer: Evidence를 PASS/WARNING/FAIL Finding으로 해석, severity와 recommendation 부여
- Scoring: Analyzer가 만든 Finding 기반 score와 grade 계산
- Reporter: ScanResult와 comparison 결과를 JSON/HTML artifact로 출력
- AI Formatter: rule-based JSON 중 허용된 필드만 사용한 설명과 요약 생성
- Config/Utils: 공통 설정과 보조 기능 제공

의존성 방향:

```text
CLI
  ↓
Scanner / Analyzer / Comparison / Reporter
  ↓
Models / Config / Utils
```

금지 구조:

- Reporter가 Scanner를 직접 호출하는 구조
- Analyzer가 CLI를 참조하는 구조
- LLM이 Finding, severity, evidence, CVE를 새로 생성하는 구조
- Rule-based 결과보다 LLM 결과를 우선하는 구조

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
- `evidence`와 `interpretation` 분리
- Security Score gauge, severity cards, Executive Summary cards, category/OWASP sections 기반 HTML UI 개선

### v2.1

- Optional Ollama AI Report integration
- model: `qwen2.5:7b`
- endpoint: `http://localhost:11434/api/generate`
- Ollama unavailable/failure 시 graceful fallback
- LLM 입력을 rule-based scan JSON으로 제한하는 구조
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
- pytest 20 passed

### v2.3

- Architecture Refactoring
- CLI command separation
- Comparison module separation
- Scoring module separation
- Common models introduction
- Reporter boundary separation
- Rule Engine foundation
- Dependency cleanup
- Backward compatibility maintained
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

HTML report 마지막의 Optional AI Report Formatter section. 해당 section 안내문:

```text
Findings were detected by the rule-based engine. The LLM only summarized and explained the results.
```

AI Report Formatter 안전 장치:

- LLM은 취약점 탐지자가 아닌 report formatter
- scanner/analyzer가 생성한 rule-based JSON 중 허용 field만 AI 입력으로 전달
- raw HTTP response, debug log, internal exception text 제외
- schema validation 및 sanitizing 적용
- invalid/freeform response 시 scanner-derived fallback 사용
- rule-based JSON/HTML report 생성 실패와 분리된 선택 기능

## Sample Reports

검증 과정에서 생성된 sample report:

- [Korean AI sample](docs/samples/sample_v2_ko_ai.html)
- [English AI sample](docs/samples/sample_v2_en_ai.html)

matching sample JSON:

- `reports/sample_v2_ko.json`
- `reports/sample_v2_en.json`

## Roadmap

완료:

- v2.3 Architecture Refactoring
- CLI command separation
- Comparison module separation
- Scoring module separation
- Reporter boundary separation
- Rule Engine foundation

향후 계획:

- Validation Lab
- Audit Trail
- Before/After HTML Report
- Security Improvement Timeline
- DI(Data Integrity) support
- LLM Provider expansion, 낮은 우선순위

## License

MIT License.
