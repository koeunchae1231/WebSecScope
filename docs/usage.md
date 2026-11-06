# 실행·정책·리포트 안내

저장소 루트 기준 실행 안내임. 제품 코드·운영 정책 예제·로컬 환경 설정을 분리한 구성임.

## 설치 및 로컬 서버

Python 표준 라이브러리 기반이며 테스트 의존성은 pytest임. 검증 환경은 Windows 11·Python 3.13.14임. 로컬 CLI 확인은 외부 CVE 조회와 Linux/Docker 관측을 제외한 조건임.

```powershell
python -m pip install -r requirements.txt
python -m pip install pytest
python -m http.server 8080 --bind 127.0.0.1 --directory docs/samples
```

서버는 첫 터미널에 유지하고 아래 명령은 두 번째 터미널에서 실행하는 방식임. 종료 시 첫 터미널의 Ctrl+C 사용이 필요한 상태임.

## 기본 명령

```powershell
python main.py --help
python main.py scan --help
python main.py report --help
python main.py recheck --help
python main.py scan --target http://127.0.0.1:8080/ --skip-linux --skip-docker --skip-service-detect --skip-cve --output reports/repository_local.json
python main.py report --input reports/repository_local.json --output reports/repository_local.html
python main.py scan --target http://127.0.0.1:8080/ --lang en --skip-linux --skip-docker --skip-service-detect --skip-cve --output reports/repository_en.json
python main.py report --input reports/repository_en.json --lang en --output reports/repository_en.html
```

| 옵션 | 의미 |
|---|---|
| `--target` | 소유 또는 허가받은 대상 URL |
| `--output` | 생성 파일 경로 |
| `--lang {ko,en}` | 출력 언어, 기본 ko |
| `--policy` | origin에 결합된 서비스 선언 |
| `--skip-api-auth` | 기본 활성 API/Auth 제외 |
| `--skip-linux`, `--skip-docker` | 기본 활성 로컬 관측 제외 |
| `--skip-service-detect`, `--skip-cve` | 기본 활성 서비스 식별·NVD 조회 제외 |

Linux/Docker는 로컬 실행 환경과 접근 권한에 의존하는 관측임. 웹 서비스의 원격 호스트 내부를 자동 검사한다는 의미가 아님.

## 정책 설정

[policy.example.json](../policy.example.json)은 복사 가능한 UTF-8 예제이며 운영 환경 설정과 구분되는 서비스 요구 선언임. 기존 예제와 스키마는 변경하지 않았음.

| 항목 | 적용 범위 |
|---|---|
| `policy_version: 1` | 지원 스키마 버전 |
| `target_origin` | scheme·host·port 일치, 대상 불일치 거부 |
| `resources` | 정확한 절대 경로의 public/private 선언, 패턴 제외 |
| `cookies` | authentication/session/preference/unknown 용도와 domain/path 범위 |
| `header_requirements.required_headers` | 헤더 존재 요구 |
| `header_requirements.strength` | 헤더 강도 요구 |

```powershell
python main.py scan --target http://127.0.0.1:8080/ --policy policy.example.json --skip-linux --skip-docker --skip-service-detect --skip-cve --output reports/repository_policy.json
python main.py report --input reports/repository_policy.json --output reports/repository_policy.html
```

지원 강도는 CSP `p2-restricted-script-object`, Referrer-Policy `no-cross-origin-full-url`, Permissions-Policy `{"deny_features":["camera","microphone","geolocation"]}`임. 헤더 범위는 `scope: origin` 또는 정확한 `path`임. JavaScript가 필요한 비민감 preference의 HttpOnly 면제는 Secure/SameSite 요구를 면제하지 않음. 공개 선언도 실제 비밀 노출을 무조건 허용하는 근거가 아님.

[정책 스키마](../websecscope/policy.py), [헤더 요구 구현](../websecscope/rules/web/header_requirements.py)이 상세 기준임. 실제 서비스 계약에 맞는 origin·경로·요구 설정이 필요한 상태임.

## 변경 전후 비교

```powershell
python main.py recheck --before reports/repository_local.json --after reports/repository_policy.json --output reports/repository_recheck.json
```

위 명령은 정책 차이 비교 예제임. 보안 수정 효과를 평가할 때는 동일 대상·언어·정책의 수정 전후 스캔을 입력해야 하는 조건임.

## JSON·HTML과 선택 AI

JSON은 `findings`, `all_findings`, `findings_summary`, `score`, `grade`, `score_details`, `language`와 Finding별 status·risk·evidence·recommendation·metadata·skipped를 보존하는 형식임. HTML은 점수 근거·위험 요약·상세 Finding·분류별 결과를 표시하는 형식임. [한국어 샘플](samples/sample_v2_ko_ai.html)은 과거 표시 예시임.

Ollama는 선택 기능임. `ollama pull qwen2.5:7b`, `ollama serve` 후 같은 report 명령을 사용하는 방식임. 기본 endpoint는 `http://localhost:11434/api/generate`임.

| 환경변수 | 용도 |
|---|---|
| `WEBSECSCOPE_OLLAMA_URL` | endpoint |
| `WEBSECSCOPE_OLLAMA_MODEL` | model |
| `WEBSECSCOPE_OLLAMA_TIMEOUT` | timeout |
| `WEBSECSCOPE_OLLAMA_TEMPERATURE` | temperature |

연결·응답 검증 실패 시 rule-based 설명으로 대체하는 구조임. LLM은 Finding·점수 생성자가 아님. 저장소 정리의 명령 검증은 모델 추론·외부 NVD 호출을 제외한 fallback 경로 확인임.

## 테스트 및 자료 보존

```powershell
python -m pytest -q -p no:cacheprovider --basetemp=.pytest-local/repository-cleanup
```

기존 테스트 기준은 407개임. 과거 임시 결과를 보존해야 할 때는 `--basetemp`에 새로운 하위 경로 지정이 필요한 상태임. `pytest.ini`는 tests/만 수집하는 설정임. 최종 원시 근거와 동결 소스는 단일 evidence.zip으로 통합한 보존 자료임.

[평가·재현 안내](evaluation.md)에 최종 근거와 검증 명령을 정리했음.
