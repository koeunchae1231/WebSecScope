# WebSecScope (WSS)

Linux 서버 기반 웹 서비스 보안 진단 플랫폼

---

## 1. Project Overview

### Description

* Python 기반 Linux 서버 보안 진단 도구
* 웹 애플리케이션, Linux 서버, Docker 컨테이너 통합 분석

### Tech Stack

* Python
* Linux
* Docker
* NVD API

 ### Deliverables

* HTML Report
* JSON Report

### Development Method

* Requirements-driven Development
* Generative AI Assisted Development
* Human Verification

---

## 2. Project Background

* VitaCore 개발 및 Render(Linux) 배포 경험
* Linux 서버 운영 환경 경험
* 반복적인 보안 진단 자동화 필요성
* 개발 프로젝트 기반 보안 진단 플랫폼 설계

---

## 3. Project Goals

* 웹 서비스 보안 진단
* Linux 서버 보안 진단
* Docker 컨테이너 보안 진단
* Backend API 보안 분
* CVE / CVSS 분석
* Security Score 산출
* 개선 가이드
* 재검증
* HTML / JSON 리포트

---

## 4. Target Environment

### Analysis Target

* Web Application
* Linux Server
* Docker Container

### Development Environment

* Windows
* WSL2 Ubuntu
* Docker Desktop

### Deployment Environment

* Render
* AWS EC2

---

## 5. Scope

### 5.1 Included

* 허가된 대상 보안 진단
* 웹 서비스 보안 점
* Backend API 분석
* 인증 및 인가 분석
* Linux 서버 보안 점검
* Docker 컨테이너 보안 점검
* CVE 조회
* CVSS 분석
* Security Score 산출
* 개선 가이드
* 재검증
* HTML / JSON 리포트 생성

### 5.2 Excluded

* 허가되지 않은 대상 공격
* Brute Force 공격
* DDoS 공격
* 악성코드 제작
* 데이터 변조 및 삭제
* 권한 없는 침투 행위
* Windows 서버 보안 진단

---

## 6. Design Principles

* Modular Architecture
* Rule-based Analysis
* Linux Server Based
* Defensive Security
* Evidence-based Analysis
* Report-driven Result

---

## 7. System Modules

* Scanner
* Analyzer
* Guide
* Reporter
* Visualizer

---

## 8. Core Features

### 8.1 Web Security Scan

#### Scan Items

* HTTP Security Header
* HTTPS / TLS
* Cookie Security
* Directory Exposure
* Server Information Exposure
* Security Misconfiguration

---

### 8.2 Backend API & Authentication Analysis

#### Analysis Items

* REST API
* JWT Authentication
* Token Validation
* Authorization
* IDOR
* Broken Access Control
* CORS
* Rate Limit
* Error Message Exposure

---

### 8.3 Linux Security Scan

#### Scan Items

* Open Port
* Running Service
* SSH Configuration
* Firewall
* File Permission
* Package Version

---

### 8.4 Docker Security Scan

#### Scan Items

* Root User
* Privileged Mode
* Latest Tag
* Secret Exposure
* Host Network
* Volume Mount

---

### 8.5 CVE / CVSS Analysis

#### Analysis Items

* Service Detection
* Version Detection
* CVE Lookup
* CVSS Score
* Risk Classification
* CVSS Visualization

---

### 8.6 Improvement Guide

#### Guide Items

* Risk Description
* Cause Analysis
* Fix Guide
* Configuration Example
* Command Example

---

### 8.7 Recheck

#### Verification Items

* Previous Result
* Current Result
* Before / After
* PASS / FAIL Change

---

### 8.8 Security Visualization

#### Visualization Items

* Overall Security Score
* Category Score
* CVSS Distribution
* Risk Distribution
* Security History

---

### 8.9 Security Report

#### Report Items

* Executive Summary
* Security Score
* Finding List
* CVE / CVSS Summary
* Improvement Guide
* Recheck Result

---

## 9. Workflow
```
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

CVE Lookup

↓

CVSS Analysis

↓

Risk Classification

↓

Improvement Guide

↓

Security Score Calculation

↓

Recheck

↓

Security Visualization

↓

HTML / JSON Report Generation
```
