# WebSecScope 코드 구조

전체 흐름과 각 module의 책임을 이해하기 위한 문서.

WebSecScope는 rule-based 보안 진단 도구. Scanner와 Analyzer가 finding을 만들고, Reporter가 결과를 JSON/HTML로 출력하는 구조. LLM과 Ollama는 이미 만들어진 rule-based 결과를 설명하고 정리하는 선택 기능. 탐지XXX.

## 1. 전체 실행 흐름

```text
main.py
    ↓
cli.py
    ↓
scanner/orchestrator.py
    ↓
scanner/*
    ↓
analyzer/*
    ↓
models.py
    ↓
reporter/*
```

Report 단계 내부 흐름:

```text
JSON Report
    ↓
Safe LLM Payload
    ↓
AI Report Formatter
    ↓
Output Validation / Sanitizing
    ↓
Scanner-derived Fallback if invalid
    ↓
HTML Renderer
```

핵심 책임 분리:

- Scanner: 관찰 가능한 evidence 수집
- Analyzer: evidence를 finding으로 해석
- Score Calculator: score와 grade 계산
- JSON Reporter: machine-readable 결과 저장
- AI Report Formatter: scanner-approved 결과 설명
- HTML Reporter: 검증·정리된 결과 렌더링

## 2. `main.py`

`main.py`는 프로젝트의 가장 작은 entry point.

역할:

- Python 실행 진입점
- 실제 CLI 로직을 직접 가지지 않는 구조
- `websecscope.cli.main()` 호출만 담당

예시:

```python
from websecscope.cli import main

if __name__ == "__main__":
    main()
```

설계 의도:

- `python main.py ...` 실행 편의성
- CLI 로직과 package 구조 분리
- 테스트와 재사용을 위한 import 가능한 CLI 구조

## 3. `cli.py`

`cli.py`는 사용자의 command line 입력을 읽고 작업 흐름을 선택하는 계층.

주요 명령:

- `scan`: target 진단 및 JSON report 생성
- `report`: 기존 JSON result를 HTML report로 변환
- `recheck`: 이전 JSON과 현재 JSON 비교

주요 option:

- `--target`
- `--output`
- `--input`
- `--lang ko`
- `--lang en`
- `--skip-linux`
- `--skip-docker`
- `--skip-cve`

`scan` 흐름:

```text
CLI input
    ↓
run_scan(...)
    ↓
write_json_report(...)
```

`report` 흐름:

```text
JSON file
    ↓
load_json(...)
    ↓
write_html_report(...)
```

설계 의도:

- CLI 입력을 보안 분석 로직으로 직접 해석하지 않는 구조
- option 값을 정리해 다음 계층으로 전달하는 얇은 계층
- scan logic과 report logic의 CLI 결합 최소화

## 4. scanner

Scanner는 evidence를 수집하는 계층. Scanner가 최종 취약점을 판단하지 않는 구조. 판단XXX.

Scanner의 책임:

- HTTP status, header, cookie 관찰
- Linux/Docker local state 관찰
- service/version signal 수집
- analyzer가 해석 가능한 구조화 evidence 생성

### `scanner/orchestrator.py`

전체 scan 흐름을 조립하는 파일.

역할:

- Web scan 연결
- API/Auth scan 연결
- Linux scan 연결
- Docker scan 연결
- Service/version detection 연결
- CVE analysis 연결
- 최종 `ScanResult` 생성

반환 데이터:

- `ScanResult`
- Scanner와 Analyzer가 만든 finding 목록
- JSON/HTML report 생성에 필요한 scan metadata

### `scanner/web.py`

검사 내용:

- target URL 형식
- target reachability
- HTTP security header
- Cookie security attribute
- Sensitive path response status

설계 의도:

- 웹에서 관찰 가능한 HTTP response 기반 점검
- `403` 같은 status를 바로 취약점으로 확정하지 않는 구조
- `evidence`와 `interpretation` 분리

### `scanner/linux.py` / `scanner/linux_scanner.py`

검사 내용:

- Linux listening port
- OS / kernel / hostname 정보
- SSH 설정
- firewall 상태
- file permission
- account 관련 기본 신호

설계 의도:

- Linux host의 read-only evidence 수집
- 권한 부족 또는 비-Linux 환경에서 skipped 상태 기록
- destructive action 없음

### `scanner/docker_scanner.py`

검사 내용:

- Docker CLI 사용 가능 여부
- running container metadata
- image tag
- privileged mode
- root user
- network mode
- mount
- environment key 이름

설계 의도:

- container hardening 검토에 필요한 metadata 수집
- secret value 수집 없음
- secret처럼 보이는 key 이름만 evidence로 기록

### `scanner/service_detector.py`

검사 내용:

- listening TCP port
- port 기반 service 후보

설계 의도:

- CVE lookup과 service exposure 판단을 위한 inventory 생성
- 이 단계 자체는 취약점 판단XXX

### `scanner/version_detector.py`

검사 내용:

- SSH banner
- HTTP/HTTPS server header
- product/version signal

설계 의도:

- CVE/CVSS 분석에 필요한 product/version 근거 생성
- version 정보 부족 시 confidence로 과신 방지

## 5. analyzer

Analyzer는 Scanner가 수집한 evidence를 finding으로 해석하는 계층.

Analyzer의 책임:

- `PASS`, `WARNING`, `FAIL` status 부여
- risk level 부여
- recommendation 연결
- OWASP category 연결
- evidence와 interpretation 분리 유지

### Findings 생성 과정

Finding은 WebSecScope report의 핵심 단위.

주요 field:

- `check_id`
- `category`
- `title`
- `status`
- `risk`
- `evidence`
- `recommendation`
- `metadata`

### API/Auth Analyzer

관련 파일:

- `analyzer/api_auth_analyzer.py`

역할:

- API documentation 노출 가능성 분석
- admin path 노출 가능성 분석
- authentication 누락 가능성 분석
- JWT 구조 검토
- CORS policy 검토
- IDOR 후보 signal 검토
- rate-limit header signal 검토

설계 의도:

- 단일 response만으로 confirmed vulnerability를 과장하지 않는 구조
- review signal 중심 finding 생성

### Linux Analyzer

관련 파일:

- `analyzer/linux_analyzer.py`

역할:

- SSH 설정 해석
- firewall 상태 해석
- file permission 해석
- account 상태 해석
- open port 해석

### Docker Analyzer

관련 파일:

- `analyzer/docker_analyzer.py`

역할:

- privileged container 판단
- root user 실행 판단
- latest/missing image tag 검토
- host network / namespace 사용 검토
- risky mount / capability 검토
- exposed port 검토

### CVE

관련 파일:

- `analyzer/cve.py`

역할:

- service/version evidence 기반 NVD CVE API 조회
- CVE item normalize
- confidence 계산
- CVE finding 생성

주의점:

- CVE 결과는 potentially related 정보
- 배포 환경, vendor advisory, package patch 여부에 따른 수동 검증 필요

### CVSS

CVSS는 CVE item의 심각도를 정규화하는 기준.

기본 매핑:

- `9.0+`: `CRITICAL`
- `7.0+`: `HIGH`
- `4.0+`: `MEDIUM`
- `0.1+`: `LOW`
- unknown: `INFO`

### OWASP

관련 파일:

- `owasp.py`

역할:

- finding의 `check_id` 또는 `category`를 OWASP Top 10 category로 매핑

예시:

- Missing CSP → `A05 Security Misconfiguration`
- Sensitive path exposure → `A05 Security Misconfiguration`
- Auth/session finding → `A07 Identification and Authentication Failures`
- CVE finding → `A06 Vulnerable and Outdated Components`

### Score 계산

관련 파일:

- `analyzer/score.py`

역할:

- finding 목록 기반 0~100 Security Score 계산
- severity별 penalty 적용
- skipped scan 제외
- duplicate finding 완화
- confidence 기반 penalty 조정

설계 의도:

- report를 읽는 사람이 전체 상태를 빠르게 이해하기 위한 guide
- score 자체가 절대적 보안 보증은 아님

## 6. models

관련 파일:

- `models.py`

역할:

- `Finding` dataclass 정의
- `ScanResult` dataclass 정의
- JSON report dictionary 생성
- finding summary 생성
- severity count와 top-risk 목록 생성

v2.2 변경:

- top-risk detail card 렌더링을 위한 `interpretation`, `description`, `recommendation` field 포함
- HTML Reporter가 top-risk card에서 description, impact, recommendation, evidence를 분리 표시할 수 있는 구조

## 7. reporter

Reporter는 분석 결과를 사람이 읽거나 도구가 재사용할 수 있는 artifact로 변환하는 계층.

### JSON Report

관련 파일:

- `reporter/json_reporter.py`

생성 순서:

```text
ScanResult
    ↓
ScanResult.to_dict()
    ↓
save_json(...)
    ↓
result.json
```

역할:

- machine-readable 결과 저장
- recheck 입력
- HTML report 입력
- Safe LLM Payload 생성의 원천 데이터

### HTML Report

관련 파일:

- `reporter/html_reporter.py`

생성 순서:

```text
result.json
    ↓
load_json(...)
    ↓
write_html_report(...)
    ↓
result.html
```

HTML report 주요 section:

- Security Score explanation
- Executive Summary
- Severity cards
- Top-risk cards
- Detailed finding cards
- Category/OWASP summary
- Web/API/Auth/Linux/Docker/Service/CVE sections
- Optional AI Report Formatter section

v2.2 UI 개선:

- score explanation 추가
- executive summary 개선
- top-risk cards 개선
- detailed finding cards 추가
- better spacing/wrapping/typography
- localized section labels
- 한국어 리포트의 raw Markdown marker와 영어 section label 노출 방지

설계 의도:

- JSON은 도구 친화적 결과물
- HTML은 사람 친화적 결과물
- 긴 문단을 table에 몰아넣지 않는 card 기반 상세 표시

### AI Report Formatter

관련 파일:

- `reporter/llm_report_generator.py`
- `reporter/html_reporter.py`

생성 순서:

```text
JSON Report
    ↓
Safe LLM Payload
    ↓
AI Report Formatter
    ↓
Output Validation / Sanitizing
    ↓
Scanner-derived Fallback if invalid
    ↓
HTML Renderer
```

역할:

- rule-based JSON 중 허용 field만 선택
- Korean/English prompt 생성
- Ollama API 호출
- AI output validation/sanitizing
- schema 불일치 또는 freeform 응답 시 scanner-derived fallback text 생성
- HTML Reporter가 sanitized result만 렌더링하도록 결과 반환

강조점:

- LLM은 탐지XXX
- LLM은 severity 생성XXX
- LLM은 CVE 생성XXX
- LLM은 evidence 생성XXX
- LLM은 endpoint 생성XXX
- LLM은 scanner-approved fields만 사용
- LLM output은 schema validation 대상
- schema validation 실패 시 fallback 사용
- HTML Reporter는 AI 결과를 신뢰하기 전에 sanitized result만 렌더링

## 8. AI Report

AI Report 흐름:

```text
config/settings.py
    ↓
llm_report_generator.py
    ↓
Ollama
    ↓
output validation / sanitizing
    ↓
html_reporter.py
```

### `config/settings.py`

역할:

- Ollama endpoint
- model name
- timeout
- temperature
- environment variable override

설계 의도:

- 설정값과 코드 로직 분리
- 배포 환경마다 다른 Ollama 설정을 코드 수정 없이 적용하는 구조

### `llm_report_generator.py`

역할:

- AI 입력으로 허용되는 scanner-approved field 선택
- raw HTTP response, debug log, internal exception text 제외
- JSON formatter 중심 prompt 생성
- Ollama API 호출
- AI output validation/sanitizing
- Markdown marker, HTML, 내부 오류 메시지 제거 또는 무시
- invalid/freeform output에 대한 scanner-derived fallback 생성

강조점:

- LLM은 보안 분석기가 아닌 report formatter
- LLM은 finding 생성XXX
- LLM은 severity 변경XXX
- LLM은 CVE, endpoint, evidence invent XXX
- LLM은 rule-based 결과 설명과 정리만 담당

### Ollama

역할:

- local LLM runtime
- `qwen2.5:7b` model 기반 report formatter 응답 생성

실패 가능성:

- Ollama 미실행
- model 미설치
- timeout
- API error
- schema 불일치 응답
- freeform 응답

실패 처리:

- Ollama request failure 시 graceful fallback
- schema invalid 또는 freeform 응답 시 scanner-derived fallback
- 일반 JSON/HTML report 생성 유지

### `html_reporter.py`

역할:

- scanner/analyzer 결과를 HTML section으로 렌더링
- score explanation, executive summary, severity cards 렌더링
- top-risk cards와 detailed finding cards 렌더링
- localized section labels 적용
- AI Report Formatter 결과 중 sanitized result만 렌더링
- fallback message 또는 scanner-derived fallback section 렌더링

설계 의도:

- AI Report는 부가 기능
- AI 실패가 전체 report 실패로 이어지지 않는 구조
- HTML에 raw Markdown marker, stack trace, internal exception text 노출 방지

## 9. 데이터 흐름

```text
Target
    ↓
Scanner
    ↓
Evidence
    ↓
Analyzer
    ↓
Findings
    ↓
Score Calculator
    ↓
ScanResult
    ↓
JSON Report
    ↓
HTML Report
    ↓
Optional AI Report Formatter section
```

### Target

사용자가 진단을 허가한 URL 또는 local runtime 환경.

### Scanner

Target에서 evidence 수집.

예시:

- HTTP status
- HTTP header
- Cookie
- open port
- Docker metadata
- service banner

### Evidence

Scanner가 관찰한 원자료에 가까운 구조화 데이터.

주의점:

- raw HTTP response 전체를 AI에 전달하지 않는 구조
- report에 필요한 최소 근거 중심 저장

### Analyzer

Evidence를 finding으로 해석.

예시:

- header 누락 → security misconfiguration finding
- Docker privileged mode → high risk finding
- service/version → CVE lookup candidate

### Findings

WebSecScope report의 핵심 단위.

포함 정보:

- 무엇을 검사했는지
- 결과가 PASS/WARNING/FAIL 중 무엇인지
- risk 수준이 어느 정도인지
- 근거 evidence가 무엇인지
- 해석 interpretation이 무엇인지
- 어떤 조치를 권장하는지
- OWASP category가 무엇인지

### Score Calculator

Finding severity와 상태를 기반으로 score와 grade 계산.

### JSON Report

scanner/analyzer/score 결과의 기준 artifact.

### HTML Report

사용자에게 보여주는 사람이 읽기 쉬운 artifact.

### Optional AI Report Formatter section

검증된 scanner-derived 정보만 바탕으로 한 설명 section. 탐지XXX.

## 10. 프로젝트를 공부하는 추천 순서

1. `main.py`

   가장 작은 실행 진입점 확인.

2. `websecscope/cli.py`

   사용자의 명령이 어떤 함수로 연결되는지 확인.

3. `websecscope/scanner/orchestrator.py`

   전체 scan 흐름과 Scanner/Analyzer 연결 방식 확인.

4. `websecscope/scanner/web.py`

   HTTP 기반 evidence 수집과 sensitive path status 해석 방식 확인.

5. `websecscope/models.py`

   `Finding`, `ScanResult`, JSON field 생성 방식 확인.

6. `websecscope/analyzer/`

   evidence가 finding으로 바뀌는 과정 확인.

7. `websecscope/reporter/html_reporter.py`

   JSON 결과가 HTML section, score explanation, top-risk card, finding card로 바뀌는 과정 확인.

8. `websecscope/reporter/llm_report_generator.py`

   rule-based JSON이 Safe LLM Payload로 제한되고 validation/sanitizing/fallback을 거치는 과정 확인.

9. `docs/architecture/CodeStructure.md` 재독

   코드 확인 후 전체 흐름을 다시 연결하기 위한 문서.

이 순서로 보면 WebSecScope가 입력 → 수집 → 해석 → 구조화 → 출력 → 선택형 설명으로 움직이는 흐름 이해 가능.
