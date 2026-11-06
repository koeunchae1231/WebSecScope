# WebSecScope

## 1. 프로젝트 소개

**HTTP 응답 증거와 서비스 정책을 함께 활용하는 Python 보안 진단 CLI임.**  
상태 코드만으로 취약점을 확정하지 않고, 본문·헤더·쿠키·운영 요구를 확인하는 구조임.  
판정 근거와 점수 감점 내역을 JSON·HTML로 제공하며, 근거 부족 시 판정 보류를 지원함.

## 2. 주요 기능

| 기능 | 구현 범위 |
|---|---|
| 웹·API·인증 진단 | 보안 헤더, 쿠키 속성, 민감 경로의 본문 증거, API 문서·관리 경로, 인증·CORS 신호 |
| 서비스 정책 | 공개·비공개 경로, 쿠키 용도, 헤더 존재·강도 요구, origin 검증 |
| 로컬 환경·버전 점검 | Linux·Docker 관측, 서비스 식별, NVD CVE/CVSS 조회 |
| 결과·개선 확인 | JSON·HTML 리포트, 변경 전후 비교, 범위·위험·신뢰도·중복을 반영한 점수 근거 |
| 선택 AI 설명 | Ollama 기반 결과 설명, 연결 실패 시 기본 설명으로 대체 |

브라우저 실행·취약점 exploit·실제 권한 우회 검증은 지원 범위 밖임.  
로컬 환경 점검은 원격 웹 서버 내부 검사를 의미하지 않음.  
소유하거나 명시적으로 허가받은 대상에서만 사용하는 도구임.

## 3. 기술 스택

| 구분 | 기술 |
|---|---|
| 구현 | Python, argparse, urllib, http.client, 표준 라이브러리 |
| 출력·연동 | JSON, HTML, NVD API, Ollama API |
| 검증 | pytest, 로컬 HTTP fixture, OWASP ZAP Passive Scan 비교 |
| 검증 환경 | Windows 11, Python 3.13.14 |

제품 실행에 외부 Python 패키지는 필요하지 않으며 테스트 의존성은 pytest임.

## 4. 정량 성과

신규 내부 합성 홀드아웃 **100개** 중 정답 확정 **80개: 취약 40·정상 40**, unknown **20개**임.  
3조건 × 3반복의 **900회 실행**이며, 반복은 독립 표본이 아님.  
아래 지표는 첫 반복 기준임.

| 정책 조건 | 조건부 Precision | 조건부 Recall | 조건부 F1 | Coverage | 전체 취약 탐지율 |
|---|---:|---:|---:|---:|---:|
| 없음 `none` | 76.92% | 86.96% | 81.63% | 50/80 · 62.50% | 20/40 · 50.00% |
| 경로·쿠키 `p1` | 95.00% | 86.36% | 90.48% | 51/80 · 63.75% | 19/40 · 47.50% |
| 경로·쿠키·헤더 요구 `headers` | **96.43%** | **100%** | **98.18%** | **57/80 · 71.25%** | **27/40 · 67.50%** |

조건부 지표는 보류·오류를 제외한 값임.  
Coverage는 정답 확정 80개 중 확정 판정 비율이며, 전체 취약 탐지율은 취약 40개 중 탐지 비율임.  
`headers`의 TP/FP/FN/TN/보류는 **27/1/0/29/23**임.  
코드 동결 후 작성한 동일 작성자의 내부 합성 평가이며, 외부 독립 평가·실서비스 정확도를 의미하지 않음.

| 검증 | 결과 |
|---|---|
| 전체 테스트 | pytest **407개 통과** |
| 주요 CLI | 도움말·한국어/영어/정책 scan·HTML report·recheck **11개 명령 성공** |
| 최종 평가 근거 | 원시 기록 900회와 ZAP 비교 52회에서 공개 지표 재계산 확인 |
| ZAP 공통 비교 | 정책 없는 정답 확정 20개에서 조건부 Precision **85.71% / 69.23%**, Coverage **70% / 100%** — WebSecScope / ZAP 순서임. |

ZAP은 동일 HTTP 증거를 HAR로 반입한 Passive Scan 조건임.  
경고 의미·정책 입력·HTTP 수집 범위·프로세스 생명주기가 달라 완전한 동등 비교가 아님.  
사례 단위 양성은 원래 취약 원인의 정확한 탐지와 구분되며, 속도·메모리 우열의 근거로 사용하지 않음.  
[평가 범위·원시 근거·재현 안내](docs/evaluation.md)에 상세 기준을 정리했음.

## 5. 설치 및 실행

Python 3.10 이상 환경에서 저장소 루트 기준 명령임.  
첫 터미널의 로컬 예제 서버를 유지한 상태에서 두 번째 터미널의 scan·report 실행이 필요함.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pip install pytest
python -m http.server 8080 --bind 127.0.0.1 --directory docs/samples
```

```powershell
python main.py scan --target http://127.0.0.1:8080/ --skip-linux --skip-docker --skip-service-detect --skip-cve --output reports/local.json
python main.py report --input reports/local.json --output reports/local.html
python -m pytest -q
python tools/verify_evidence.py
```

정적 예제 서버의 헤더 누락 경고도 진단 결과임.  
검증 후 서버 종료는 Ctrl+C 방식임.  
[정책·옵션·결과 비교 안내](docs/usage.md), [MIT License](LICENSE) 참고 항목임.
