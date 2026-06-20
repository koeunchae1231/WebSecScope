# WebSecScope (WSS)

Python 기반 웹 서비스, Linux 서버, Docker 컨테이너 보안 진단 CLI
반복되는 점검의 자동화를 위함

## 1. 프로젝트 소개

| 항목 | 내용 |
| --- | --- |
| 프로젝트명 | WebSecScope (WSS) |
| 한 줄 소개 | 허가된 웹 서비스와 서버 환경을 대상으로 한 read-only 보안 진단 CLI |
| 핵심 목적 | 웹, API/Auth, Linux, Docker, CVE/CVSS 결과를 하나의 JSON/HTML 리포트로 통합 |
| 개발 방식 | Requirements-driven Development, Generative AI Assisted Development, Human Verification |
| 산출물 | JSON Report, HTML Report, Recheck Result |

### 프로젝트 개요

WebSecScope는 웹 애플리케이션, Linux 서버, Docker 컨테이너 환경의 기본 보안 상태를 점검하기 위한 Python 기반 CLI 도구.

주요 진단 결과는 finding 단위로 정규화되며, 각 finding은 severity, evidence, recommendation, Security Score 계산에 연결되는 구조.

### 개발 배경

| 배경 | 설명 |
| --- | --- |
| Linux 기반 배포 경험 | Render, AWS EC2, Docker 기반 운영 환경에서 반복적인 점검 필요 |
| 웹 서비스 보안 점검 반복성 | 보안 헤더, API 노출, Docker 설정, Linux 기본 설정의 반복 확인 필요 |
| 포트폴리오형 보안 자동화 | 기획 문서 기반 MVP 구현, 보고서 중심 결과물 |

### 해결하고자 한 문제

- 웹 보안 헤더 점검과 서버 보안 점검의 분리 문제
- Linux, Docker, API/Auth, CVE 결과의 흩어진 evidence 문제
- 수동 점검 결과의 재검증 어려움
- 보안 점검 결과의 포트폴리오용 HTML 리포트화 필요

### CLI 형태 설계 이유

- 서버, WSL, CI, 로컬 개발 환경에서 동일한 실행 흐름
- 별도 웹 서버 없이 빠른 진단과 리포트 생성
- JSON 결과 저장과 recheck 비교에 적합한 단일 진입점
- 자동화 스크립트와 결합하기 쉬운 명령 기반 인터페이스

### Linux 기반 설계 이유

- 운영 서버 보안 점검의 주요 대상
- `/proc`, `/etc`, SSH 설정, firewall 도구, Docker CLI와의 자연스러운 결합
- Windows/macOS 환경에서는 Linux 전용 점검을 `skipped`로 처리하는 호환 구조

## 2. 주요 기능

| 기능 | 점검 대상 | 결과 |
| --- | --- | --- |
| Web Security Header Scan | HTTP Security Header, Cookie 속성, 민감 경로 후보 | PASS / FAIL / WARNING, risk, evidence, recommendation |
| API / Authentication Analysis | `/api`, `/api/login`, `/api/admin`, `/swagger`, `/openapi.json` 등 후보 경로 | 인증 누락 가능성, 보호 상태, API 문서/관리자 경로 노출 징후 |
| JWT Structure Analysis | 응답 헤더, 쿠키, 본문 샘플의 JWT-like token | header/payload 구조 분석, `alg:none`, exp 누락, 민감 key 징후 |
| CORS Analysis | `Access-Control-Allow-*` 헤더 | wildcard origin, credential 조합, origin reflection 의심 |
| IDOR Heuristic Review | 숫자 ID 기반 URL 패턴 | 확정 취약점이 아닌 review recommended finding |
| Rate Limit Signal Check | 로그인/인증 후보 경로 | `X-RateLimit-*`, `Retry-After` 헤더 관찰 |
| Linux Security Scan | OS, kernel, SSH, firewall, 파일 권한, 계정 기본 점검 | Linux 전용 read-only 점검, 비Linux 환경 skipped |
| Docker Security Scan | 실행 컨테이너, 이미지, 권한, 네트워크, 볼륨, env key | Docker CLI 기반 read-only 점검, Docker 미사용 환경 skipped |
| Service Detection | Linux listening TCP port | 포트 기반 service name, protocol, confidence |
| Version Detection | SSH banner, HTTP/HTTPS version header | product/version 정규화, CVE lookup 기반 데이터 |
| NVD CVE Lookup | detected product/version | NVD CVE API 2.0 기반 potentially related CVE, CVSS |
| CVSS Analysis | NVD CVSS v3.1, v3.0, v2 | severity 정규화, score 반영 |
| Security Score | 통합 findings | 0-100 score, A-F grade |
| JSON Report | scan 결과 전체 | machine-readable result |
| HTML Report | scan 또는 recheck 결과 | single-file portfolio report |
| Recheck | 이전 JSON과 현재 JSON | score delta, grade delta, resolved/new/unchanged findings |

## 3. 전체 동작 흐름

```text
Target Input

↓

Web Security Scan

↓

Backend API & Authentication Analysis

↓

Linux Security Scan

↓

Docker Security Scan

↓

Service Detection

↓

Version Detection

↓

NVD CVE Lookup

↓

CVSS Analysis

↓

Risk Classification

↓

Improvement Guide Mapping

↓

Security Score / Grade

↓

JSON Report

↓

HTML Report

↓

Recheck
```

## 4. 프로젝트 구조

| 모듈 | 역할 |
| --- | --- |
| `main.py` | CLI 실행 진입점 |
| `websecscope/cli.py` | argparse 기반 command, option 처리 |
| `websecscope/scanner/` | 웹, API/Auth, Linux, Docker, service/version 원자료 수집 |
| `websecscope/analyzer/` | scanner 결과 기반 finding 생성, CVE/CVSS, score, recheck |
| `websecscope/guide/` | finding별 recommendation 매핑 |
| `websecscope/reporter/` | JSON 저장, HTML 리포트 생성 |
| `websecscope/visualizer/` | HTML 표시용 score/status class helper |
| `websecscope/models.py` | Finding, ScanResult, summary schema |
| `websecscope/utils.py` | JSON load/save, output path helper |

## 5. 아키텍처

```text
CLI

↓

Scanner

↓

Analyzer

↓

Guide Mapping

↓

Security Score

↓

Reporter

↓

JSON / HTML Result
```

### 데이터 흐름

```text
main.py
  → websecscope.cli
    → scanner.orchestrator.run_scan()
      → scanner modules
      → analyzer modules
      → guide mappings
      → score calculation
      → ScanResult
    → reporter.json_reporter
    → reporter.html_reporter
```

## 6. 디렉터리 구조

```text
WebSecScope/
├── main.py
├── README.md
└── websecscope/
    ├── __init__.py
    ├── cli.py
    ├── models.py
    ├── utils.py
    ├── scanner/
    │   ├── __init__.py
    │   ├── api_scanner.py
    │   ├── auth_scanner.py
    │   ├── docker_scanner.py
    │   ├── linux.py
    │   ├── linux_scanner.py
    │   ├── orchestrator.py
    │   ├── service_detector.py
    │   ├── version_detector.py
    │   └── web.py
    ├── analyzer/
    │   ├── __init__.py
    │   ├── api_auth_analyzer.py
    │   ├── cve.py
    │   ├── docker_analyzer.py
    │   ├── linux_analyzer.py
    │   ├── recheck.py
    │   ├── score.py
    │   └── service_analyzer.py
    ├── guide/
    │   ├── __init__.py
    │   └── mappings.py
    ├── reporter/
    │   ├── __init__.py
    │   ├── html_reporter.py
    │   └── json_reporter.py
    └── visualizer/
        ├── __init__.py
        └── html.py
```

## 7. 실행 방법

### 요구사항

| 항목 | 기준 |
| --- | --- |
| Python | Python 3.10 이상 권장 |
| 외부 Python 패키지 | v1.0 기준 필수 패키지 없음 |
| Linux 점검 | Linux 런타임 권장 |
| Docker 점검 | Docker CLI 및 Docker daemon 접근 권한 |
| CVE 조회 | 인터넷 연결, 선택 사항 `NVD_API_KEY` |

### 설치

```bash
git clone https://github.com/koeunchae1231/WebSecScope.git
cd WebSecScope
```

### 가상환경

```bash
python -m venv .venv
```

Windows:

```bash
.venv\Scripts\activate
```

Linux / macOS:

```bash
source .venv/bin/activate
```

### 기본 스캔

```bash
python main.py scan --target https://example.com
```

### JSON 저장 경로 지정

```bash
python main.py scan --target https://example.com --output reports/result.json
```

### HTML 리포트 생성

```bash
python main.py report --input reports/result.json
```

### Recheck 비교

```bash
python main.py recheck --before reports/before.json --after reports/result.json
```

### NVD API Key 선택 설정

Windows:

```bash
set NVD_API_KEY=your_api_key
```

Linux / macOS:

```bash
export NVD_API_KEY=your_api_key
```

## 8. CLI 옵션

### Commands

| Command | 설명 |
| --- | --- |
| `scan` | 대상 URL 기준 통합 보안 점검 |
| `report` | JSON 결과 기반 HTML 리포트 생성 |
| `recheck` | 이전 JSON과 현재 JSON 비교 |

### `scan` 옵션

| 옵션 | 기본값 | 설명 |
| --- | --- | --- |
| `--target` | 필수 | 허가된 대상 URL |
| `--output` | 자동 생성 | JSON 결과 저장 경로 |
| `--api-auth` | 포함 | API/Auth 분석 명시 포함 |
| `--skip-api-auth` | 미사용 | API/Auth 분석 제외 |
| `--service-detect` | 포함 | Service/Version Detection 명시 포함 |
| `--skip-service-detect` | 미사용 | Service/Version Detection 제외 |
| `--cve` | 포함 | NVD CVE/CVSS 조회 명시 포함 |
| `--skip-cve` | 미사용 | NVD CVE/CVSS 조회 제외 |
| `--linux` | 포함 | Linux Security Scan 명시 포함 |
| `--skip-linux` | 미사용 | Linux Security Scan 제외 |
| `--docker` | 포함 | Docker Security Scan 명시 포함 |
| `--skip-docker` | 미사용 | Docker Security Scan 제외 |

### `report` 옵션

| 옵션 | 설명 |
| --- | --- |
| `--input` | 입력 JSON 경로 |
| `--output` | 출력 HTML 경로, 미지정 시 input 확장자만 `.html` |

### `recheck` 옵션

| 옵션 | 설명 |
| --- | --- |
| `--before` | 이전 scan JSON |
| `--after` | 현재 scan JSON |
| `--output` | recheck JSON 저장 경로, 기본값 `reports/recheck.json` |

## 9. 결과 예시

### `result.json`

```json
{
  "scan_id": "...",
  "version": "1.0.0",
  "target": "https://example.com",
  "score": 94,
  "grade": "A",
  "findings_summary": {
    "total": 12,
    "critical": 0,
    "high": 0,
    "medium": 1,
    "low": 2,
    "informational": 7,
    "categories": {},
    "top_risks": []
  },
  "all_findings": [],
  "api_scan": {},
  "auth_scan": {},
  "linux_scan": {},
  "docker_scan": {},
  "service_detection": {},
  "version_detection": {},
  "cve_lookup": {}
}
```

| 섹션 | 내용 |
| --- | --- |
| `score`, `grade` | 통합 Security Score와 A-F 등급 |
| `findings_summary` | severity별 집계, category별 집계, top risks |
| `all_findings` | 전체 finding 목록 |
| `api_auth_findings` | API/Auth/JWT/CORS/IDOR/Rate Limit 관련 finding |
| `linux_findings` | Linux Security Scan 관련 finding |
| `docker_findings` | Docker Security Scan 관련 finding |
| `service_findings` | Service/Version Detection 관련 finding |
| `cve_findings` | NVD CVE/CVSS 관련 finding |

### `result.html`

| 섹션 | 내용 |
| --- | --- |
| Executive Summary | target, score, grade, finding count |
| Findings Summary by Severity | critical, high, medium, low, informational |
| Top Risks | 우선 검토 finding |
| Web Security | 웹 보안 헤더, cookie, 민감 경로 결과 |
| API/Auth Security | API/Auth, JWT, CORS, IDOR, rate limit 결과 |
| Service & Version Detection | 포트 기반 service, banner/header 기반 version |
| CVE/CVSS | NVD 결과, CVSS, confidence |
| Linux Security | Linux system, SSH, firewall, file/account 점검 |
| Docker Security | Docker container, image, privilege, volume, env key 점검 |
| All Findings | 전체 finding 표 |

### `recheck.json`

```json
{
  "before_score": 96,
  "after_score": 94,
  "score_delta": -2,
  "before_grade": "A",
  "after_grade": "A",
  "severity_delta": {},
  "resolved_findings": [],
  "new_findings": [],
  "unchanged_findings": [],
  "changes": []
}
```

## 10. Security Score

### Severity 기준

| Severity | 기본 감점 |
| --- | --- |
| critical | -25 |
| high | -15 |
| medium | -8 |
| low | -3 |
| informational | 0 |

### Grade 기준

| Score | Grade |
| --- | --- |
| 90-100 | A |
| 80-89 | B |
| 70-79 | C |
| 60-69 | D |
| 0-59 | F |

### 보정 기준

| 조건 | 처리 |
| --- | --- |
| low confidence finding | 감점 50% 이하 완화 |
| medium confidence finding | 감점 완화 |
| skipped scan | 감점 제외 |
| 동일 category/title 중복 finding | 중복 감점 완화 |
| CVE finding | CVSS score와 confidence 동시 고려 |
| 최종 score | 0-100 범위 제한 |

## 11. 사용 기술

| 분류 | 기술 |
| --- | --- |
| Language | Python |
| CLI | argparse |
| Data Model | dataclasses |
| Network | urllib, socket, ssl |
| Report | HTML, JSON |
| CVE | NVD CVE API 2.0 |
| Linux | `/proc/net/tcp`, `/etc/os-release`, `/etc/ssh/sshd_config`, read-only shell commands |
| Docker | Docker CLI, `docker ps`, `docker inspect`, `docker version` |
| Runtime Utility | pathlib, subprocess, stat, platform |
| Version Control | Git, GitHub |

## 12. 안전성(Safety)

WebSecScope v1.0 MVP의 기본 원칙:

- Read-only 기반 점검
- 시스템 설정 변경 없음
- 서비스 재시작 없음
- 컨테이너 stop/rm/exec/cp/run 없음
- 실제 공격 수행 없음
- 인증 우회 없음
- 무차별 대입 없음
- 파괴적 요청 없음
- 과도한 스캔 없음
- 환경변수 value 출력 없음

### CVE/CVSS 주의사항

| 항목 | 설명 |
| --- | --- |
| CVE 매칭 성격 | NVD keywordSearch 기반 참고 정보 |
| 확정 취약점 여부 | 확정 판정 아님 |
| 필요한 후속 조치 | 제품 버전, 배포 설정, vendor advisory 기반 수동 검증 |
| confidence | product/version matching 신뢰도 보조 지표 |

## 13. 지원 환경

| 환경 | 동작 |
| --- | --- |
| Linux | Web/API/Auth, Linux, Docker, Service/Version, CVE, Report, Recheck |
| Windows | Web/API/Auth, Report, Recheck, Docker CLI 존재 시 Docker 점검 가능 |
| macOS | Web/API/Auth, Report, Recheck, Docker CLI 존재 시 Docker 점검 가능 |
| WSL2 Ubuntu | Linux Security Scan과 Docker Desktop 연동 환경에 적합 |
| Docker Desktop | Docker CLI와 daemon 접근 가능 시 Docker Security Scan |

### 환경별 skipped 처리

| 상황 | 처리 |
| --- | --- |
| 비Linux 환경 | `linux_scan.status = "skipped"` |
| Docker CLI 없음 | `docker_scan.status = "skipped"` |
| Docker daemon 미실행 | `docker_scan.status = "skipped"` |
| NVD 네트워크 실패 | `cve_lookup.errors`와 evidence 기록 |
| 권한 부족 | finding evidence 또는 skipped reason 기록 |

## 14. Roadmap

### v1.1

| 항목 | 상태 |
| --- | --- |
| Package Version Inventory | 계획 항목, 미구현 |
| SSH 설정 Include 파일 확장 파싱 | 계획 항목 |
| Firewall rule 상세 위험도 분석 | 계획 항목 |
| CVE CPE 기반 relevance 개선 | 계획 항목 |
| HTML Recheck 전용 레이아웃 강화 | 계획 항목 |
| Category Score | ProjectPlan 항목, 미구현 |

### v2.0

| 항목 | 상태 |
| --- | --- |
| Security History | ProjectPlan 항목, 미구현 |
| CVSS Distribution Chart | ProjectPlan 항목, 미구현 |
| Risk Distribution Visualization | ProjectPlan 항목, 일부 summary만 구현 |
| CI/CD 연동 리포트 | 향후 계획 |
| 대시보드형 UI | 향후 계획 |

## 15. License

MIT License

## 16. v1.0 MVP 범위 명시

| 구현 완료 | Roadmap 분리 |
| --- | --- |
| Web Security Header Scan | Category Score |
| API/Auth Analysis | Security History |
| JWT/CORS/IDOR/Rate Limit 분석 | CVSS Chart |
| Linux Security Scan | Package Inventory |
| Docker Security Scan | Dashboard UI |
| Service/Version Detection | CI/CD Policy Gate |
| NVD CVE/CVSS Lookup | Advanced CPE Matching |
| Security Score / Grade |  |
| JSON/HTML Report |  |
| Recheck |  |
