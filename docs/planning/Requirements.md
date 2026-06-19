# Requirements

## 1. Web Security Scan
- URL 입력
- HTTP Header 수집
- Security Header 점검
- Cookie 속성 점검
- 민감 경로 노출 점검

## 2. Linux Security Scan
- 열린 포트 수집
- 실행 서비스 수집
- SSH 설정 점검
- 방화벽 상태 점검

## 3. Docker Security Scan
- 실행 컨테이너 수집
- root 사용자 실행 여부 점검
- privileged 옵션 점검
- latest 태그 점검
- 환경변수 secret 노출 점검

## 4. CVE / CVSS Analysis
- 서비스명 수집
- 버전 정보 수집
- NVD API 조회
- CVSS 점수 수집
- 위험도 분류

## 5. Improvement Guide
- Finding별 개선 가이드 매핑
- 설정 예시 제공
- 명령어 예시 제공

## 6. Recheck
- 이전 스캔 결과 저장
- 재검사 결과 비교
- PASS / FAIL 변화 표시

## 7. Report
- JSON 결과 저장
- HTML 리포트 생성
- Security Score 표시
- CVE / CVSS 요약 표시
