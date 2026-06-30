# WebSecScope 코드 구조

WebSecScope 내부 구조와 각 module 책임 정리 문서.

핵심 구조는 `Scanner -> Analyzer -> Reporter -> Optional AI Formatter` 흐름. Rule-based Engine이 Single Source of Truth이며, LLM은 탐지자가 아닌 Report Formatter 역할.

## 1. 전체 실행 흐름

```text
main.py
    ↓
websecscope/cli/main.py
    ↓
websecscope/cli/commands/*
    ↓
scanner/orchestrator.py
    ↓
scanner/*
    ↓
rules/*
    ↓
analyzer/*
    ↓
scoring/*
    ↓
models.py
    ↓
reporter/*
    ↓
JSON / HTML Report
```

Report 단계 내부 흐름:

```text
Rule-based JSON
    ↓
Safe LLM Payload
    ↓
Optional AI Report Formatter
    ↓
Output Validation / Sanitizing
    ↓
Scanner-derived Fallback if invalid
    ↓
HTML Renderer
```

핵심 책임:

- Scanner: 관측 가능한 Evidence 생성
- Rules: scanner 판단 기준과 rule catalog 제공
- Analyzer: Evidence 기반 Finding 판단
- Scoring: Finding 기반 score와 grade 계산
- Comparison: before/after 결과 비교
- Reporter: JSON/HTML 출력
- AI Formatter: scanner-approved 결과 설명
- Models: Evidence, Finding, ScanResult 공통 모델
- Config/Utils: 공통 설정과 보조 기능

## 2. 프로젝트 구조

```text
websecscope/
    cli/
        main.py
        commands/
            scan.py
            report.py
            recheck.py
    scanner/
        orchestrator.py
        web.py
        api_scanner.py
        auth_scanner.py
        linux_scanner.py
        docker_scanner.py
        service_detector.py
        version_detector.py
    rules/
        web/
            headers.py
            paths.py
    analyzer/
        api_auth_analyzer.py
        linux_analyzer.py
        docker_analyzer.py
        service_analyzer.py
        cve.py
        recheck.py
        score.py
    comparison/
        comparator.py
        delta.py
        summary.py
        html.py
    scoring/
        calculator.py
        weights.py
        grade.py
    reporter/
        html_reporter.py
        json_reporter.py
        llm_report_generator.py
        html/
        json/
        ai/
    models.py
    config/
        settings.py
    utils.py
```

## 3. CLI

관련 파일:

- `websecscope/cli/main.py`
- `websecscope/cli/commands/scan.py`
- `websecscope/cli/commands/report.py`
- `websecscope/cli/commands/recheck.py`

역할:

- argparse parser 구성
- command별 option 정의
- command handler dispatch
- public CLI interface 유지

설계 의도:

- CLI와 scan/report/recheck 실행 책임 분리
- command별 테스트와 확장 가능 구조
- `from websecscope.cli import main` 호환 유지

## 4. Scanner

Scanner는 Evidence 생성 계층. 최종 취약점 판단이 아닌 관측 가능한 신호 수집 책임.

역할:

- HTTP status, header, cookie 관측
- API/Auth candidate endpoint 관측
- Linux local state read-only 관측
- Docker metadata read-only 관측
- service/version signal 수집

주의:

- Scanner 단독으로 severity 확정 금지
- exploit 실행 금지
- destructive action 금지
- Analyzer가 해석 가능한 구조의 Evidence 생성

## 5. Rules

관련 파일:

- `websecscope/rules/web/headers.py`
- `websecscope/rules/web/paths.py`

역할:

- scanner가 참조하는 rule catalog 제공
- security header 목록과 risk metadata 분리
- sensitive path 목록 분리
- 신규 rule 추가 시 scanner 수정 최소화 기반

현재 상태:

- Web rule foundation 구축
- 향후 `api`, `auth`, `docker`, `linux`, `common` rule 확장 가능 구조

## 6. Analyzer

Analyzer는 Evidence 기반 판단 계층.

역할:

- `PASS`, `WARNING`, `FAIL` status 부여
- risk level 부여
- recommendation 연결
- OWASP category 연결
- `evidence`와 `interpretation` 분리 유지

관련 파일:

- `analyzer/api_auth_analyzer.py`
- `analyzer/linux_analyzer.py`
- `analyzer/docker_analyzer.py`
- `analyzer/service_analyzer.py`
- `analyzer/cve.py`

호환 파일:

- `analyzer/recheck.py`: `comparison.compare_results` compatibility wrapper
- `analyzer/score.py`: `scoring.calculate_score`, `scoring.grade_for_score` compatibility wrapper

## 7. Evidence와 Finding 모델

관련 파일:

- `websecscope/models.py`

주요 모델:

- `Evidence`
- `Finding`
- `ScanResult`

Finding 주요 field:

- `check_id`
- `category`
- `title`
- `status`
- `risk`
- `evidence`
- `recommendation`
- `metadata`
- `id`
- `severity`
- `description`
- `interpretation`
- `owasp_category`

설계 의도:

- Finding 생성 인터페이스 통일
- Evidence 표현 방식 통일 기반
- Reporter와 AI Formatter가 같은 rule-based 결과를 참조하는 구조

## 8. Scoring

관련 파일:

- `websecscope/scoring/calculator.py`
- `websecscope/scoring/weights.py`
- `websecscope/scoring/grade.py`

역할:

- Finding 기반 Security Score 계산
- severity별 penalty weight 관리
- skipped scan 제외
- duplicate finding penalty 완화
- confidence 기반 penalty 조정
- grade 계산

설계 원칙:

- Score는 Rule-based 결과 기반
- LLM 결과의 score 영향 없음
- `analyzer/score.py` 기존 import 경로 호환

## 9. Comparison

관련 파일:

- `websecscope/comparison/comparator.py`
- `websecscope/comparison/delta.py`
- `websecscope/comparison/summary.py`
- `websecscope/comparison/html.py`

역할:

- before/after scan result 비교
- finding state 계산
- score delta 계산
- severity delta 계산
- summary 생성

state 종류:

- `IMPROVED`
- `REGRESSED`
- `CHANGED`
- `NEW`
- `RESOLVED`
- `UNCHANGED`

설계 의도:

- Analyzer에서 recheck 책임 분리
- Before/After HTML Report 확장 기반
- Security Improvement Timeline 확장 기반

## 10. Reporter

Reporter는 출력 계층. Scanner 직접 호출 금지.

관련 파일:

- `websecscope/reporter/json/writer.py`
- `websecscope/reporter/html/writer.py`
- `websecscope/reporter/ai/__init__.py`
- `websecscope/reporter/json_reporter.py`
- `websecscope/reporter/html_reporter.py`
- `websecscope/reporter/llm_report_generator.py`

역할:

- JSON report 생성
- HTML report 생성
- localization 적용
- Optional AI Report Formatter section 렌더링

호환 구조:

- `reporter/json_reporter.py` 기존 import 경로 유지
- `reporter/html_reporter.py` 기존 HTML renderer 유지
- `reporter/__init__.py` public reporter API 유지

## 11. AI Report Formatter

관련 파일:

- `websecscope/reporter/llm_report_generator.py`
- `websecscope/reporter/ai/__init__.py`
- `websecscope/config/settings.py`

역할:

- rule-based JSON 중 허용 field만 입력으로 사용
- Korean/English prompt 생성
- Ollama API 호출
- AI output validation
- Markdown/internal text sanitizing
- invalid/freeform output 시 scanner-derived fallback 생성

금지 사항:

- LLM의 Finding 생성
- LLM의 severity 변경
- LLM의 CVE 생성
- LLM의 endpoint/evidence invent
- LLM 결과의 score 영향

## 12. Config

관련 파일:

- `websecscope/config/settings.py`

역할:

- Ollama endpoint
- model name
- timeout
- temperature
- environment variable override

환경변수:

- `WEBSECSCOPE_OLLAMA_URL`
- `WEBSECSCOPE_OLLAMA_MODEL`
- `WEBSECSCOPE_OLLAMA_TIMEOUT`
- `WEBSECSCOPE_OLLAMA_TEMPERATURE`

## 13. 의존성 방향

권장 방향:

```text
CLI
  ↓
Scanner / Analyzer / Comparison / Reporter
  ↓
Scoring / Rules / Models
  ↓
Config / Utils
```

유지 원칙:

- Reporter가 Scanner를 직접 호출하지 않는 구조
- Analyzer가 CLI를 참조하지 않는 구조
- Scoring이 Reporter를 참조하지 않는 구조
- Models가 CLI/Reporter를 참조하지 않는 구조
- LLM이 Rule-based 결과를 변경하지 않는 구조

## 14. v2.3 구현 상태

완료 항목:

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

## 15. 향후 확장 기반

v3 후보:

- Validation Lab
- Audit Trail
- Before/After HTML Report
- Security Improvement Timeline
- DI(Data Integrity) support
- LLM Provider expansion, 낮은 우선순위

## 16. 코드 확인 추천 순서

1. `main.py`
2. `websecscope/cli/main.py`
3. `websecscope/cli/commands/`
4. `websecscope/scanner/orchestrator.py`
5. `websecscope/scanner/`
6. `websecscope/rules/`
7. `websecscope/analyzer/`
8. `websecscope/scoring/`
9. `websecscope/comparison/`
10. `websecscope/models.py`
11. `websecscope/reporter/`

이 순서로 확인 가능한 입력, 관측, 판단, 점수, 비교, 출력 흐름.
