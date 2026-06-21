# WebSecScope 코드 구조

이 문서는 WebSecScope의 코드 구조를 공부하기 위한 안내 문서입니다. 코드 한 줄씩 설명하기보다, 전체 흐름과 각 모듈이 왜 나뉘어 있는지 이해하는 데 목적이 있습니다.

WebSecScope는 rule-based 보안 진단 도구입니다. Scanner와 Analyzer가 finding을 만들고, Reporter가 결과를 JSON/HTML로 출력합니다. LLM과 Ollama는 탐지기가 아니라 이미 만들어진 rule-based 결과를 요약하고 설명하는 선택 기능입니다.

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
reporter/*
```

### `main.py`

- 왜 존재하는가: Python 실행 진입점을 단순하게 유지하기 위한 파일입니다.
- 입력: 사용자가 입력한 command line.
- 출력: 직접 결과를 만들지 않고 `cli.py`로 실행 흐름을 넘깁니다.
- 다음 단계로 전달하는 것: `websecscope.cli.main()` 호출.

### `cli.py`

- 왜 존재하는가: 사용자의 CLI 입력을 해석하고 어떤 작업을 실행할지 결정하기 위한 계층입니다.
- 입력: `scan`, `report`, `recheck` 명령과 option.
- 출력: scan 결과 JSON 저장, HTML report 생성, recheck 결과 저장.
- 다음 단계로 전달하는 것: target URL, output path, language, skip option 등.

### `scanner/orchestrator.py`

- 왜 존재하는가: 여러 Scanner와 Analyzer를 순서대로 연결하는 중앙 실행 흐름입니다.
- 입력: target URL과 CLI option.
- 출력: `ScanResult`.
- 다음 단계로 전달하는 것: Scanner가 수집한 raw evidence와 Analyzer가 만든 finding 목록.

### `scanner/*`

- 왜 존재하는가: 외부 대상이나 로컬 환경에서 관찰 가능한 evidence를 수집하기 위한 계층입니다.
- 입력: target URL, 로컬 Linux/Docker 환경, network response 등.
- 출력: HTTP status, header, open port, Docker metadata, service/version 같은 관찰 데이터.
- 다음 단계로 전달하는 것: Analyzer가 해석할 수 있는 구조화된 evidence.

### `analyzer/*`

- 왜 존재하는가: Scanner가 수집한 evidence를 보안 finding으로 해석하기 위한 계층입니다.
- 입력: Scanner의 관찰 데이터.
- 출력: `Finding` 객체 목록.
- 다음 단계로 전달하는 것: status, risk, evidence, recommendation, metadata가 포함된 finding.

### `reporter/*`

- 왜 존재하는가: 분석 결과를 사람이 읽거나 도구가 소비할 수 있는 파일로 만들기 위한 계층입니다.
- 입력: `ScanResult` 또는 scan result JSON.
- 출력: JSON Report, HTML Report, Optional AI Report section.
- 다음 단계로 전달하는 것: 파일 시스템에 저장되는 report artifact.

이 구조의 핵심은 책임 분리입니다. Scanner는 관찰만 하고, Analyzer는 해석하고, Reporter는 표현합니다. 이렇게 나누면 새로운 검사 항목이나 새로운 report 형식을 추가할 때 기존 흐름을 크게 흔들지 않아도 됩니다.

---

## 2. main.py

`main.py`는 프로젝트의 가장 작은 entry point입니다.

역할:

- Python이 처음 실행하는 파일.
- 실제 CLI 로직을 직접 갖지 않음.
- `websecscope.cli.main()` 호출만 담당.

왜 필요한가:

- 사용자가 `python main.py ...` 형태로 실행하기 쉽게 하기 위한 얇은 진입점입니다.
- 실제 로직을 `websecscope/cli.py` 안에 두면 package 구조가 깔끔해집니다.
- 테스트나 재사용 시 CLI 로직을 직접 import하기 쉬운 구조가 됩니다.

호출 대상:

```python
from websecscope.cli import main

if __name__ == "__main__":
    main()
```

`main.py`는 문 역할만 합니다. 문을 열면 바로 `cli.py`로 들어가는 구조입니다.

---

## 3. cli.py

`cli.py`는 사용자의 명령을 읽고 알맞은 작업으로 분기하는 파일입니다.

### argparse 처리

`argparse`는 CLI option을 정의하고 검증하는 Python 표준 라이브러리입니다.

WebSecScope의 주요 명령:

- `scan`: target을 진단하고 JSON report 생성.
- `report`: 기존 JSON result를 HTML report로 변환.
- `recheck`: 이전 JSON과 현재 JSON을 비교.

주요 option:

- `--target`
- `--output`
- `--input`
- `--lang ko`
- `--lang en`
- `--skip-linux`
- `--skip-docker`
- `--skip-cve`

### scan/report 명령 분기

`scan` 명령은 `scanner/orchestrator.py`의 `run_scan()`으로 연결됩니다.

```text
CLI input
    ↓
run_scan(...)
    ↓
write_json_report(...)
```

`report` 명령은 기존 JSON 파일을 읽고 `html_reporter.py`로 전달합니다.

```text
JSON file
    ↓
load_json(...)
    ↓
write_html_report(...)
```

### 사용자 입력 전달 방식

CLI는 사용자의 입력을 보안 분석 로직으로 직접 해석하지 않습니다. 대신 option 값을 정리해서 다음 계층에 전달합니다.

예시:

- `--target`: Scanner가 진단할 URL
- `--lang`: JSON/HTML report language
- `--skip-cve`: CVE lookup 실행 여부
- `--output`: report 저장 위치

이렇게 CLI를 얇게 유지하면, scan logic과 report logic이 CLI에 묶이지 않습니다.

---

## 4. scanner

Scanner는 evidence를 수집하는 계층입니다. 중요한 점은 Scanner가 최종 취약점 판단을 하지 않는다는 것입니다. Scanner는 “무엇이 관찰되었는가”를 기록하고, Analyzer가 “그 의미가 무엇인가”를 판단합니다.

### `scanner/orchestrator.py`

전체 scan 흐름을 조립하는 파일입니다.

검사 대상:

- Web scan
- API/Auth scan
- Linux scan
- Docker scan
- Service/version detection
- CVE analysis 연결

반환 데이터:

- `ScanResult`
- 내부적으로는 여러 Scanner와 Analyzer가 만든 finding 목록

이 파일은 “전체 scan을 어떤 순서로 실행할 것인가”를 보여주는 지도 역할입니다.

### `scanner/web.py`

검사 내용:

- target URL 형식
- target reachability
- HTTP security header
- Cookie security attribute
- Sensitive path response status

반환 데이터:

- `Finding` 목록
- header 누락 여부
- cookie flag 상태
- sensitive path에 대한 `evidence`와 `interpretation`

설계 이유:

- Web에서 관찰 가능한 HTTP response를 기반으로 가장 기본적인 보안 상태를 확인하기 위한 Scanner입니다.
- `403` 같은 status를 바로 취약점으로 단정하지 않고, `protected but exists`처럼 evidence와 interpretation을 분리합니다.

### `scanner/linux.py`와 `scanner/linux_scanner.py`

검사 내용:

- Linux listening port
- OS / kernel / hostname 정보
- SSH 설정
- firewall 상태
- file permission
- account 관련 기본 신호

반환 데이터:

- Linux host evidence dictionary
- open port 목록
- SSH/firewall/file/account 관련 raw data

설계 이유:

- Linux 환경에서는 보안 진단에 필요한 정보가 `/proc`, `/etc`, system command 등에 흩어져 있습니다.
- Scanner는 가능한 범위에서 read-only로 수집하고, 권한이 부족하거나 Linux가 아니면 skipped 상태로 남깁니다.

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

반환 데이터:

- Docker scan dictionary
- container 목록
- image 목록
- Docker unavailable/skipped reason

설계 이유:

- Docker 보안은 container 실행 option에서 중요한 신호가 나옵니다.
- 값 자체가 민감할 수 있는 secret은 수집하지 않고, secret처럼 보이는 key 이름만 evidence로 남기는 구조입니다.

### `scanner/service_detector.py`

검사 내용:

- listening TCP port
- port 기반 service 후보

반환 데이터:

- service detection item 목록
- port, protocol, service name, confidence

설계 이유:

- CVE lookup이나 service exposure 판단을 하려면 먼저 어떤 service가 열려 있는지 알아야 합니다.
- 이 단계는 정밀한 취약점 판단이 아니라 inventory 생성에 가깝습니다.

### `scanner/version_detector.py`

검사 내용:

- SSH banner
- HTTP/HTTPS server header
- 관찰 가능한 product/version signal

반환 데이터:

- normalized service item
- product
- version
- confidence
- evidence

설계 이유:

- CVE/CVSS 분석은 product/version 정보가 있어야 가능성이 높아집니다.
- version 정보가 없을 수 있으므로 confidence를 함께 두어 과신을 줄입니다.

---

## 5. analyzer

Analyzer는 Scanner가 수집한 evidence를 finding으로 바꾸는 계층입니다.

Scanner가 “무엇을 봤는가”를 말한다면, Analyzer는 “그래서 어떤 보안 의미가 있는가”를 정리합니다.

### Findings 생성 과정

Finding은 WebSecScope의 핵심 결과 단위입니다.

주요 field:

- `check_id`
- `category`
- `title`
- `status`
- `risk`
- `evidence`
- `recommendation`
- `metadata`

Analyzer는 raw evidence를 보고 `PASS`, `WARNING`, `FAIL` 중 하나의 status와 risk level을 부여합니다.

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

설계 이유:

- API/Auth 영역은 단일 response만으로 확정 취약점을 판단하기 어렵습니다.
- 그래서 “confirmed vulnerability”보다 “review signal” 중심으로 finding을 생성합니다.

### Linux Analyzer

관련 파일:

- `analyzer/linux_analyzer.py`

역할:

- SSH 설정 해석
- firewall 상태 해석
- file permission 해석
- account 상태 해석
- open port 해석

설계 이유:

- Linux Scanner가 수집한 raw data를 운영 보안 관점의 finding으로 바꾸기 위한 계층입니다.

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

설계 이유:

- Docker metadata 자체는 단순 설정값입니다.
- Analyzer가 이 설정값을 container hardening 관점으로 해석합니다.

### CVE

관련 파일:

- `analyzer/cve.py`

역할:

- service/version evidence를 기반으로 NVD CVE API 조회
- CVE item normalize
- confidence 계산
- CVE finding 생성

주의점:

- CVE 결과는 “potentially related” 정보입니다.
- 실제 취약 여부는 배포 환경, vendor advisory, package patch 여부에 따라 수동 검증 필요.

### CVSS

CVSS는 CVE item의 심각도를 정규화하는 기준입니다.

WebSecScope는 CVSS score를 기준으로 risk를 대략 매핑합니다.

- `9.0+`: `CRITICAL`
- `7.0+`: `HIGH`
- `4.0+`: `MEDIUM`
- `0.1+`: `LOW`
- unknown: `INFO`

설계 이유:

- CVE마다 표현 방식이 다르기 때문에 report에서는 같은 기준으로 비교할 수 있어야 합니다.

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

설계 이유:

- report를 보는 사람이 finding을 OWASP 기준으로 빠르게 분류할 수 있게 하기 위한 구조입니다.

### Score 계산

관련 파일:

- `analyzer/score.py`

역할:

- finding 목록을 기반으로 0~100 Security Score 계산
- severity별 penalty 적용
- skipped scan 제외
- duplicate finding 완화
- confidence 기반 penalty 조정

설계 이유:

- 많은 finding을 한 번에 볼 때 전체 상태를 빠르게 이해하기 위한 요약 지표입니다.
- 단, score는 절대적인 보안 보증이 아니라 report를 읽기 위한 guide입니다.

---

## 6. reporter

Reporter는 분석 결과를 파일로 표현하는 계층입니다.

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
- recheck, HTML report, AI Report의 입력으로 재사용

설계 이유:

- JSON을 중심 결과물로 두면 report 형식이 늘어나도 원본 결과를 다시 사용할 수 있습니다.

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

HTML report section:

- Executive Summary
- Security Score gauge
- Severity cards
- Top Risks
- Category/OWASP summary
- Web/API/Auth/Linux/Docker/Service/CVE section
- All Findings
- AI Report

설계 이유:

- JSON은 도구가 읽기 좋고, HTML은 사람이 읽기 좋습니다.
- HTML report는 portfolio나 공유용 결과물로 보기 쉽게 구성됩니다.

### AI Report

관련 파일:

- `reporter/llm_report_generator.py`
- `reporter/html_reporter.py`

생성 순서:

```text
rule-based JSON
    ↓
safe LLM payload
    ↓
Ollama prompt
    ↓
AI summary text
    ↓
HTML AI Report section
```

설계 이유:

- rule-based finding은 정확성과 재현성을 담당합니다.
- LLM은 사람이 읽기 쉬운 executive summary와 priority recommendation을 보조합니다.
- Ollama 실패 시에도 report 생성이 깨지지 않도록 graceful fallback을 둡니다.

---

## 7. AI Report

AI Report 흐름:

```text
config/settings.py
    ↓
llm_report_generator.py
    ↓
Ollama
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

설계 이유:

- 설정값을 코드 안에 흩어 놓지 않기 위한 구조입니다.
- 배포 환경마다 다른 Ollama 설정을 코드 수정 없이 바꿀 수 있습니다.

### `llm_report_generator.py`

역할:

- rule-based JSON 중 LLM에 전달해도 되는 field만 선택
- Korean/English prompt 생성
- Ollama API 호출
- success/fallback 결과를 같은 구조로 반환

강조점:

- LLM은 탐지를 하지 않습니다.
- LLM은 새로운 finding을 만들지 않습니다.
- LLM은 severity, CVE, endpoint, evidence를 invent하지 않아야 합니다.
- LLM은 rule-based 결과를 요약하고 설명만 합니다.

### Ollama

역할:

- local LLM runtime
- `qwen2.5:7b` model 기반 summary 생성

실패 가능성:

- Ollama 미실행
- model 미설치
- timeout
- API error

이 경우 `html_reporter.py`는 fallback message를 AI Report section에 표시하고 일반 HTML report 생성을 계속합니다.

### `html_reporter.py`

역할:

- AI Report 결과를 HTML 마지막 section으로 렌더링
- success이면 LLM summary 표시
- failure이면 fallback message 표시

설계 이유:

- AI Report는 부가 기능입니다.
- AI Report 실패가 전체 report 실패로 이어지면 안 됩니다.

---

## 8. 데이터 흐름

```text
Target

↓

Scanner

↓

Analyzer

↓

Findings

↓

JSON

↓

HTML

↓

AI Report (Optional)
```

### Target

사용자가 진단을 허가한 URL 또는 로컬 실행 환경입니다.

Target은 scan의 출발점입니다.

### Scanner

Target에서 evidence를 수집합니다.

예시:

- HTTP status
- HTTP header
- Cookie
- open port
- Docker metadata
- service banner

Scanner는 가능한 한 판단보다 관찰에 집중합니다.

### Analyzer

Scanner가 모은 evidence를 finding으로 해석합니다.

예시:

- header 누락 → security misconfiguration finding
- Docker privileged mode → high risk finding
- service/version → CVE lookup candidate

Analyzer는 evidence와 interpretation을 분리해 report 신뢰도를 높입니다.

### Findings

Finding은 WebSecScope report의 핵심 단위입니다.

Finding에는 다음 정보가 들어갑니다.

- 무엇을 검사했는가
- 결과가 PASS/WARNING/FAIL 중 무엇인가
- risk가 어느 정도인가
- 근거 evidence는 무엇인가
- 어떤 조치를 권장하는가
- OWASP category는 무엇인가

### JSON

JSON은 machine-readable 결과입니다.

다른 도구, recheck, HTML report, AI Report가 재사용할 수 있는 원본 형태입니다.

### HTML

HTML은 사람이 읽기 좋은 report입니다.

Security Score, summary, table, section 구성을 통해 finding을 빠르게 파악할 수 있습니다.

### AI Report (Optional)

AI Report는 JSON에 들어 있는 rule-based 결과를 사람이 이해하기 쉬운 문장으로 요약합니다.

LLM은 탐지하지 않고, Scanner/Analyzer가 만든 결과만 설명합니다.

---

## 9. 프로젝트를 공부하는 추천 순서

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

   JSON 결과가 HTML section으로 바뀌는 과정 확인.

8. `websecscope/reporter/llm_report_generator.py`

   rule-based JSON이 LLM prompt로 바뀌고 fallback 처리되는 과정 확인.

9. `CodeStructure.md`를 다시 읽기

   코드를 한 번 본 뒤 다시 읽으면 전체 흐름이 더 선명해지는 구조.

이 순서로 보면 WebSecScope가 “입력 → 수집 → 해석 → 구조화 → 출력 → 선택적 요약”으로 움직인다는 점을 자연스럽게 이해할 수 있습니다.
