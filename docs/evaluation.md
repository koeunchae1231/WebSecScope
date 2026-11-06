# 평가 범위와 재현

## 신규 내부 합성 홀드아웃

코드 동결 후 작성한 100개 사례의 내부 합성 평가임.  
정답 확정 80개는 취약 40개·정상 40개이며, unknown 20개는 혼동행렬 밖의 사례임.  
같은 작성자의 capability-aware 평가로 외부 독립성·실서비스 대표성의 한계가 있음.

| 항목 | 보존 자료 |
|---|---|
| Ground Truth·입력 | [100개 사례](validation/final_holdout/cases.json), [fixture](validation/final_holdout/fixture.py), [정책 템플릿](validation/final_holdout/policies/) |
| 평가 계약 | [사전 등록](validation/final_holdout/preregistration.json), [참고 출처](validation/final_holdout/sources.json) |
| 최종 성과 | [metrics.json](validation/final_holdout/metrics.json), [정책별 판정 변화](validation/final_holdout/policy_transitions.json) |
| 원시 검증 | [당시 검증 결과](validation/final_holdout/verification.json), [요청 패턴](validation/final_holdout/request_patterns.json) |
| 개발용 입력 | [72개 사례](validation/development/cases.json), [정책](validation/development/policy.json), [고정 38개 사례·fixture](../tools/validation/baseline.py) |

세 정책 조건 `none`·`p1`·`headers`를 각 3회 실행한 총 900회 기록임.  
주 지표는 첫 반복이며, 반복은 안정성 확인 목적임.  
`headers`는 경로·쿠키 정책과 헤더 존재·강도 요구를 모두 제공한 조건임.

| 지표 | 정의 |
|---|---|
| 조건부 Precision | TP/(TP+FP) |
| 조건부 Recall | TP/(TP+FN) |
| 조건부 F1 | 2TP/(2TP+FP+FN) |
| Coverage | (TP+FP+FN+TN)/정답 확정 사례 수 |
| 전체 취약 탐지율 | TP/전체 취약 사례 수 |

WARNING은 ABSTAIN이며 조건부 지표에서 보류·오류를 제외하는 방식임.  
`headers`의 TP/FP/FN/TN/보류/오류는 27/1/0/29/23/0임.  
조건부 F1 98.18%·Coverage 71.25%·전체 취약 탐지율 67.50%는 이 평가 범위의 값임.  
unknown 중 오류 사례는 조건당 1개이며, 알려진 80개의 오류 0개와 구분되는 결과임.

## OWASP ZAP 비교

공통 25개 중 정답 확정 20개: 취약 9개·정상 11개, unknown 5개임.  
정책 보조 사례 1개는 주 비교에서 제외했음.  
두 조건의 공통·보조 사례 총 52회 기록임.

| 정책·도구 | TP/FP/FN/TN/보류 | 조건부 Precision | 조건부 Recall | Coverage | 전체 취약 양성 비율 |
|---|---|---:|---:|---:|---:|
| none · WebSecScope | 6/1/0/7/6 | 85.71% | 100% | 14/20 · 70% | 6/9 · 66.67% |
| none · ZAP | 9/4/0/7/0 | 69.23% | 100% | 20/20 · 100% | 9/9 · 100% |
| headers · WebSecScope | 7/1/0/7/5 | 87.50% | 100% | 15/20 · 75% | 7/9 · 77.78% |
| headers · ZAP | 9/4/0/7/0 | 69.23% | 100% | 20/20 · 100% | 9/9 · 100% |

WebSecScope가 실제 수집한 HTTP 응답을 HAR로 반입한 ZAP 2.17.0 Passive Scan 조건임.  
spider·active scan 없이 추가 대상 요청 0개를 확인한 범위임.  
정책은 WebSecScope에만 제공되므로 `headers`는 입력 조건이 다른 보조 비교임.

ZAP의 CSP 추가 강화 권고와 원래 정답의 의미가 다른 사례도 사례 단위 양성에 포함됐음.  
따라서 9/9는 원래 취약 원인 전체의 정확한 탐지를 의미하지 않음.  
NO_ALERT도 안전 확정의 근거가 아님.  
원시 ZAP 편의 status의 risk 필드 해석 오류는 보존된 전체 Alert에서 재집계한 [analysis.json](validation/tool_comparison/final_run/analysis.json)의 보정 규칙을 적용했음.

WebSecScope 시간에는 HTTP 수집이 포함되고 ZAP 시간은 HAR 반입·완료 확인 기준임.  
fresh Python과 persistent JVM, polling·시작 비용·정책 입력이 달라 속도·메모리 우열 비교에 사용할 수 없는 측정임.

비교 계약은 [preregistration.json](validation/tool_comparison/final_run/preregistration.json), 사례별 집계는 [case_results.csv](validation/tool_comparison/final_run/case_results.csv), 환경은 [environment.json](validation/tool_comparison/final_run/environment.json)에 보존했음.

## 경량 근거와 재현 명령

[evidence.zip](validation/evidence.zip)은 최종 원시 JSON 900개, 최종 HAR·Finding·Alert·메시지, 당시 실행·분석 코드, 홀드아웃 동결 소스 한 벌을 포함한 단일 근거 묶음임.  
원시 바이트와 상대 경로를 유지했으며 [evidence_manifest.json](validation/evidence_manifest.json)에 파일별 SHA-256과 ZIP 해시를 기록했음.  
과거 중간 실험·반복 로그·설치본의 보관 묶음은 아님.

```powershell
python tools/verify_evidence.py
python tools/reproduce.py --case FH-HDR-01 --mode headers --output reports/replay.json
```

첫 명령은 외부 도구·네트워크 없이 압축 근거의 해시와 최종 홀드아웃·ZAP 지표를 재계산하는 검증임.  
두 번째 명령은 변경하지 않은 제품·GT·fixture·정책의 [270개 입력 해시](validation/reproduction_hashes.json)를 확인한 뒤 로컬 사례를 새로 실행하는 방식임.  
`--case all`과 `--mode none|p1|headers`로 100개 사례의 조건별 재실행이 가능함.  
기존 결과와 같은 파일명 사용은 거부하는 구조임.

새 실행의 시간·메모리는 과거 측정의 대체값이 아님.  
ZAP 전체 실측 재현에는 별도 ZAP·Java·add-on 설치와 당시 조건 복원이 필요함.  
과거 실행기는 근거 ZIP 안의 원래 경로에 보존했으며, 현재 트리의 직접 실행 도구는 `tools/reproduce.py`와 `tools/verify_evidence.py`임.
