# LLM Report Generation Plan

## 1. Purpose
WebSecScope의 규칙 기반 스캔 결과(JSON)를 LLM에 전달하여 보안 리포트 문장, Executive Summary, 개선 가이드를 자동 생성한다.

## 2. LLM Selection
- Runtime: Ollama
- Model: Qwen2.5
- Role: Report generation only
- Security detection: Not performed by LLM

## 3. LLM Responsibility
- 스캔 결과 요약
- 위험도별 주요 이슈 정리
- 개선 우선순위 설명
- 취약점별 원인/영향/개선 방법 작성
- README/포트폴리오용 요약 생성

## 4. Non-Goals
- LLM이 취약점을 직접 탐지하지 않는다.
- LLM이 CVSS 점수를 임의 산정하지 않는다.
- LLM이 보안 판단의 최종 근거가 되지 않는다.
