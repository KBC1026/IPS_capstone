# IPS Security Capstone Project

## 📌 프로젝트 개요
웹 서버, DB 서버, IPS(Suricata), Kali 공격 환경을 분리하여  
침입 탐지 및 차단을 실험하는 보안 캡스톤 프로젝트입니다.

---

## 🏗️ 시스템 구성

- **web-server**: Flask 기반 로그인 웹 서비스
- **db-server**: MySQL 사용자 및 로그 저장
- **ips**: Suricata + iptables 기반 침입 탐지 및 차단
- **kali**: 공격 시뮬레이션 환경

---

## ⚔️ 공격 시나리오

1. Kali에서 웹 서버 대상으로 공격 수행
   - Brute Force
   - SQL Injection
   - Port Scan

2. 웹 서버 로그인 시도 기록

3. IPS 서버에서 Suricata가 공격 탐지

4. iptables를 통해 공격 IP 차단

---

## 🔐 주요 기능

- 로그인 실패 횟수 기반 계정 잠금
- 로그인 로그 DB 저장
- Suricata 룰 기반 공격 탐지
- iptables 자동 차단

---

## 🚀 실행 방법

### 1. DB 설정
```bash
mysql -u root -p < schema.sql
sudo mysql login_db < init.sql
